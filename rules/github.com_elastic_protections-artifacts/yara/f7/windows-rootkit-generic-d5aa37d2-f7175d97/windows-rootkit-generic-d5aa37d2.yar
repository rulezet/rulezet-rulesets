rule Windows_Rootkit_Generic_d5aa37d2 {
    meta:
        author = "Elastic Security"
        id = "d5aa37d2-f332-4709-a00a-1eb7fdd24b81"
        fingerprint = "df63d903f08d1fb137ecd817403a0a16b4d0f35e05dd497d8009c2b746dd9f98"
        creation_date = "2026-07-26"
        last_modified = "2026-08-11"
        description = "Subject: Shenzhen Intech Indesign Technology Co., Ltd, Version: <= 3.0.0.0"
        threat_name = "Windows.Rootkit.Generic"
        reference_sample = "d312788921ec8e92f9ccc606b51b7d940933c6bda812d293d3f713c6225305f3"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $subject_name = { 06 03 55 04 03 [2] 53 68 65 6E 7A 68 65 6E 20 49 6E 74 65 63 68 20 49 6E 64 65 73 69 67 6E 20 54 65 63 68 6E 6F 6C 6F 67 79 20 43 6F 2E 2C 20 4C 74 64 }
        $version = /V\x00S\x00_\x00V\x00E\x00R\x00S\x00I\x00O\x00N\x00_\x00I\x00N\x00F\x00O\x00\x00\x00{0,4}\xbd\x04\xef\xfe[\x00-\xff]{4}([\x00-\xff][\x00-\xff][\x00-\x02][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\xff][\x00-\xff]|[\x00-\x00][\x00-\x00][\x03-\x03][\x00-\x00][\x00-\x00][\x00-\x00][\x00-\x00][\x00-\x00])/
        $str1 = "Driver.pdb"
        $str2 = "Low-Level Driver" wide
    condition:
        int16(uint32(0x3C) + 0x5c) == 0x0001 and int16(uint32(0x3C) + 0x18) == 0x020b and $subject_name and $version and $str1 and $str2
}