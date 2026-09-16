rule Remcos_uac_disable
{
    meta:
        description = "Detects Remcos UAC disable technique."
        
    strings:
        $reg1 = "Policies\\System" ascii wide
        $reg2 = "EnableLUA" ascii wide
        $cmd = "reg.exe ADD" ascii wide nocase
        
    condition:
        uint16(0) == 0x5A4D and all of them
}