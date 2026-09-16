rule Windows_VulnDriver_Realtek_6fbf07b7 {
    meta:
        author = "Elastic Security"
        id = "6fbf07b7-bfb0-411c-a6ed-d7fe16a3fe05"
        fingerprint = "f06560888b3502129709d435af50a376bdba9a7a145025db39dc6384bf6e9f87"
        creation_date = "2026-05-22"
        last_modified = "2026-08-11"
        description = "Subject: Realtek Semiconductor Corp, Version: <= 5.0.2195.1711"
        threat_name = "Windows.VulnDriver.Realtek"
        reference_sample = "71423a66165782efb4db7be6ce48ddb463d9f65fd0f266d333a6558791d158e5"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $subject_name = { 06 03 55 04 03 [2] 52 65 61 6C 74 65 6B 20 53 65 6D 69 63 6F 6E 64 75 63 74 6F 72 20 43 6F 72 70 }
        $original_file_name = { 4F 00 72 00 69 00 67 00 69 00 6E 00 61 00 6C 00 46 00 69 00 6C 00 65 00 6E 00 61 00 6D 00 65 00 00 00 72 00 74 00 70 00 6F 00 72 00 74 00 2E 00 73 00 79 00 73 00 00 00 }
        $version = /V\x00S\x00_\x00V\x00E\x00R\x00S\x00I\x00O\x00N\x00_\x00I\x00N\x00F\x00O\x00\x00\x00{0,4}\xbd\x04\xef\xfe[\x00-\xff]{4}([\x00-\xff][\x00-\xff][\x00-\x04][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\xff][\x00-\xff]|[\x00-\x00][\x00-\x00][\x05-\x05][\x00-\x00][\x00-\xff][\x00-\xff]([\x00-\xff][\x00-\x00]|[\x00-\xff][\x01-\x07]|[\x00-\x92][\x08-\x08])|[\x00-\x00][\x00-\x00][\x05-\x05][\x00-\x00]([\x00-\xff][\x00-\x00]|[\x00-\xff][\x01-\x05]|[\x00-\xae][\x06-\x06])[\x93-\x93][\x08-\x08]|[\x00-\x00][\x00-\x00][\x05-\x05][\x00-\x00][\xaf-\xaf][\x06-\x06][\x93-\x93][\x08-\x08])/
        $str1 = "rtport.pdb"
        $str2 = "Windows (R) 2003 DDK 3790 provider" wide
        $str3 = "Generic Port I/O for Win64" wide
    condition:
        int16(uint32(0x3C) + 0x5c) == 0x0001 and int16(uint32(0x3C) + 0x18) == 0x020b and $subject_name and $original_file_name and $version and $str1 and $str2 and $str3
}