rule Windows_VulnDriver_GameDriverX64_ede96f80 {
    meta:
        author = "Elastic Security"
        id = "ede96f80-e31d-4c85-ad57-73bd94b90a20"
        fingerprint = "338430ba85b4e490ef4e149287fccb5adf7228ee238b8b66cf216fdf21ac8139"
        creation_date = "2026-05-22"
        last_modified = "2026-07-13"
        description = "Subject: Shanghai Yuelong IE Culture Technology Co., Ltd., Version: <= 7.23.4.7"
        threat_name = "Windows.VulnDriver.GameDriverX64"
        reference_sample = "9d396b83647f5233cd93f47caa05e0a0d0dd5dd2f17ba2b0ae5cd1afc0afa69d"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $subject_name = { 06 03 55 04 03 [2] 53 68 61 6E 67 68 61 69 20 59 75 65 6C 6F 6E 67 20 49 45 20 43 75 6C 74 75 72 65 20 54 65 63 68 6E 6F 6C 6F 67 79 20 43 6F 2E 2C 20 4C 74 64 2E }
        $original_file_name = { 4F 00 72 00 69 00 67 00 69 00 6E 00 61 00 6C 00 46 00 69 00 6C 00 65 00 6E 00 61 00 6D 00 65 00 00 00 47 00 61 00 6D 00 65 00 44 00 72 00 69 00 76 00 65 00 72 00 58 00 36 00 34 00 2E 00 73 00 79 00 73 00 00 00 }
        $version = /V\x00S\x00_\x00V\x00E\x00R\x00S\x00I\x00O\x00N\x00_\x00I\x00N\x00F\x00O\x00\x00\x00{0,4}\xbd\x04\xef\xfe[\x00-\xff]{4}([\x00-\xff][\x00-\xff][\x00-\x06][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\xff][\x00-\xff]|[\x00-\x16][\x00-\x00][\x07-\x07][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\xff][\x00-\xff]|[\x17-\x17][\x00-\x00][\x07-\x07][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\x03][\x00-\x00]|[\x17-\x17][\x00-\x00][\x07-\x07][\x00-\x00][\x00-\x06][\x00-\x00][\x04-\x04][\x00-\x00]|[\x17-\x17][\x00-\x00][\x07-\x07][\x00-\x00][\x07-\x07][\x00-\x00][\x04-\x04][\x00-\x00])/
        $str1 = "PwrdDriver.pdb"
        $str2 = "GameDriverX64" wide
    condition:
        int16(uint32(0x3C) + 0x5c) == 0x0001 and int16(uint32(0x3C) + 0x18) == 0x020b and $subject_name and $original_file_name and $version and $str1 and $str2
}