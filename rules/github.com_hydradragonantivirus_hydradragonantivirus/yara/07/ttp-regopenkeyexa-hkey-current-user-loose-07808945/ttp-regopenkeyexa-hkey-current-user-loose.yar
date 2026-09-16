import "pe"
rule TTP_RegOpenKeyExA_HKEY_CURRENT_USER_loose {
    meta:
        author = "@captainGeech42,@stvemillertime,@greglesnewich"
        description = "Look for PE files that try to open HKEY_CURRENT_USER keys (const 0x80000001) with RegOpenKeyExA"
        reference = "https://learn.microsoft.com/en-us/windows/win32/sysinfo/predefined-keys"
        date = "2024-01-27"
        version = "1"
        DaysofYARA = "27/100"
    strings:

        $reg_open_key_call = {01 00 00 80 [1-20] ff 15}
    condition:
        uint16be(0) == 0x4d5a and (
            $reg_open_key_call and
            for any i in (1..#reg_open_key_call): (
            for any imp in pe.import_details : (
                imp.library_name == "ADVAPI32.dll" and
                for any func in imp.functions : (
                    func.name == "RegOpenKeyExA" and
                    uint32(@reg_open_key_call[i]+!reg_open_key_call[i])&0xfffff == func.rva                     )
                )
            )
        )
}