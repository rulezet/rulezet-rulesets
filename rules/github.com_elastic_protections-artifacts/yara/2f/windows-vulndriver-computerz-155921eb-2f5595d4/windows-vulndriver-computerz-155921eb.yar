rule Windows_VulnDriver_ComputerZ_155921eb {
    meta:
        author = "Elastic Security"
        id = "155921eb-dfe8-4b21-a567-c281a6abd110"
        fingerprint = "71977dfb6172970ddb0f963c0630eb97c2f8672cd36a6aec4c8734a87ff86950"
        creation_date = "2026-05-22"
        last_modified = "2026-07-13"
        description = "Subject: 成都奇鲁科技有限公司, Version: <= 1.1020.1030.1217"
        threat_name = "Windows.VulnDriver.ComputerZ"
        reference_sample = "3f3684a37b2645fa6827943d9812ffc2d83e89e962935b29874bec7c3714a06f"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $subject_name = { 06 03 55 04 03 [2] E6 88 90 E9 83 BD E5 A5 87 E9 B2 81 E7 A7 91 E6 8A 80 E6 9C 89 E9 99 90 E5 85 AC E5 8F B8 }
        $original_file_name = { 4F 00 72 00 69 00 67 00 69 00 6E 00 61 00 6C 00 46 00 69 00 6C 00 65 00 6E 00 61 00 6D 00 65 00 00 00 43 00 6F 00 6D 00 70 00 75 00 74 00 65 00 72 00 5A 00 2E 00 53 00 79 00 73 00 00 00 }
        $version = /V\x00S\x00_\x00V\x00E\x00R\x00S\x00I\x00O\x00N\x00_\x00I\x00N\x00F\x00O\x00\x00\x00{0,4}\xbd\x04\xef\xfe[\x00-\xff]{4}([\x00-\xff][\x00-\xff][\x00-\x00][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\xff][\x00-\xff]|([\x00-\xff][\x00-\x00]|[\x00-\xff][\x01-\x02]|[\x00-\xfb][\x03-\x03])[\x01-\x01][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\xff][\x00-\xff]|[\xfc-\xfc][\x03-\x03][\x01-\x01][\x00-\x00][\x00-\xff][\x00-\xff]([\x00-\xff][\x00-\x00]|[\x00-\xff][\x01-\x03]|[\x00-\x05][\x04-\x04])|[\xfc-\xfc][\x03-\x03][\x01-\x01][\x00-\x00]([\x00-\xff][\x00-\x00]|[\x00-\xff][\x01-\x03]|[\x00-\xc0][\x04-\x04])[\x06-\x06][\x04-\x04]|[\xfc-\xfc][\x03-\x03][\x01-\x01][\x00-\x00][\xc1-\xc1][\x04-\x04][\x06-\x06][\x04-\x04])/
        $str1 = "ComputerZ.pdb"
        $str2 = "Ludashi System Driver" wide
    condition:
        int16(uint32(0x3C) + 0x5c) == 0x0001 and $subject_name and $original_file_name and $version and $str1 and $str2
}