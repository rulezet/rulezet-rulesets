rule Windows_VulnDriver_ComputerZ_046781f2 {
    meta:
        author = "Elastic Security"
        id = "046781f2-981a-4a06-ad51-9eed7f923a35"
        fingerprint = "eefcc358fa7e4f6d068a626eeff042c3c24ac52075d5f028adaea5dfbccf4ab9"
        creation_date = "2026-05-22"
        last_modified = "2026-07-13"
        description = "Subject: Chengdu Ceshi Technology Co., Ltd., Version: <= 1.1.9.416"
        threat_name = "Windows.VulnDriver.ComputerZ"
        reference_sample = "61e7f9a91ef25529d85b22c39e830078b96f40b94d00756595dded9d1a8f6629"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $subject_name = { 06 03 55 04 03 [2] 43 68 65 6E 67 64 75 20 43 65 73 68 69 20 54 65 63 68 6E 6F 6C 6F 67 79 20 43 6F 2E 2C 20 4C 74 64 2E }
        $original_file_name = { 4F 00 72 00 69 00 67 00 69 00 6E 00 61 00 6C 00 46 00 69 00 6C 00 65 00 6E 00 61 00 6D 00 65 00 00 00 43 00 6F 00 6D 00 70 00 75 00 74 00 65 00 72 00 5A 00 2E 00 53 00 79 00 73 00 00 00 }
        $version = /V\x00S\x00_\x00V\x00E\x00R\x00S\x00I\x00O\x00N\x00_\x00I\x00N\x00F\x00O\x00\x00\x00{0,4}\xbd\x04\xef\xfe[\x00-\xff]{4}([\x00-\xff][\x00-\xff][\x00-\x00][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\xff][\x00-\xff]|[\x00-\x00][\x00-\x00][\x01-\x01][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\xff][\x00-\xff]|[\x01-\x01][\x00-\x00][\x01-\x01][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\x08][\x00-\x00]|[\x01-\x01][\x00-\x00][\x01-\x01][\x00-\x00]([\x00-\xff][\x00-\x00]|[\x00-\x9f][\x01-\x01])[\x09-\x09][\x00-\x00]|[\x01-\x01][\x00-\x00][\x01-\x01][\x00-\x00][\xa0-\xa0][\x01-\x01][\x09-\x09][\x00-\x00])/
        $str1 = "ComputerZ.pdb"
        $str2 = "Zwuqi System Driver" wide
    condition:
        int16(uint32(0x3C) + 0x5c) == 0x0001 and int16(uint32(0x3C) + 0x18) == 0x020b and $subject_name and $original_file_name and $version and $str1 and $str2
}