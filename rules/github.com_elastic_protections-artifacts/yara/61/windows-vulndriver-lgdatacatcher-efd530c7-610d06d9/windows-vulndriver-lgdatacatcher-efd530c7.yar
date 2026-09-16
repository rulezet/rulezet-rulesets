rule Windows_VulnDriver_LgDataCatcher_efd530c7 {
    meta:
        author = "Elastic Security"
        id = "efd530c7-9127-46cb-b989-1456b52e3663"
        fingerprint = "ea7f482c315b9996917ffc475368da74e33e91d6b66dd321c98c7dbf3cf8e6a0"
        creation_date = "2026-05-22"
        last_modified = "2026-07-20"
        description = "Subject: 雷神（武汉）信息技术有限公司, Version: <= 1.0.0.0"
        threat_name = "Windows.VulnDriver.LgDataCatcher"
        reference_sample = "07fb2bb6c852f6a6fe982b2232f047e167be39738bac26806ffe0927ba873756"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $subject_name = { 06 03 55 04 03 [2] E9 9B B7 E7 A5 9E EF BC 88 E6 AD A6 E6 B1 89 EF BC 89 E4 BF A1 E6 81 AF E6 8A 80 E6 9C AF E6 9C 89 E9 99 90 E5 85 AC E5 8F B8 }
        $original_file_name = { 4F 00 72 00 69 00 67 00 69 00 6E 00 61 00 6C 00 46 00 69 00 6C 00 65 00 6E 00 61 00 6D 00 65 00 00 00 4C 00 67 00 44 00 61 00 74 00 61 00 43 00 61 00 74 00 63 00 68 00 65 00 72 00 2E 00 73 00 79 00 73 00 00 00 }
        $version = /V\x00S\x00_\x00V\x00E\x00R\x00S\x00I\x00O\x00N\x00_\x00I\x00N\x00F\x00O\x00\x00\x00{0,4}\xbd\x04\xef\xfe[\x00-\xff]{4}([\x00-\xff][\x00-\xff][\x00-\x00][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\xff][\x00-\xff]|[\x00-\x00][\x00-\x00][\x01-\x01][\x00-\x00][\x00-\x00][\x00-\x00][\x00-\x00][\x00-\x00])/
        $str1 = "LgDCatcher.pdb"
        $str2 = "Leigod net data catcher." wide
    condition:
        int16(uint32(0x3C) + 0x5c) == 0x0001 and int16(uint32(0x3C) + 0x18) == 0x020b and $subject_name and $original_file_name and $version and $str1 and $str2
}