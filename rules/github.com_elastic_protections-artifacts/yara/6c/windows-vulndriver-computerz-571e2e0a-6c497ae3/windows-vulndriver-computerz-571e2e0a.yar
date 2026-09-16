rule Windows_VulnDriver_ComputerZ_571e2e0a {
    meta:
        author = "Elastic Security"
        id = "571e2e0a-1d2f-465d-8c45-0dd3bcb5b97c"
        fingerprint = "aebb0a7cc6bc8a72c7e3622cc7e6929f43aa75a866cb7de58eb7727b96a58c9b"
        creation_date = "2026-05-22"
        last_modified = "2026-07-13"
        description = "Subject: Chengdu Qiying Technology Co.,Ltd., Version: <= 1.6.11.1008"
        threat_name = "Windows.VulnDriver.ComputerZ"
        reference_sample = "a97b404aae301048e0600693457c3320d33f395e9312938831bc5a0e808f2e67"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $subject_name = { 06 03 55 04 03 [2] 43 68 65 6E 67 64 75 20 51 69 79 69 6E 67 20 54 65 63 68 6E 6F 6C 6F 67 79 20 43 6F 2E 2C 4C 74 64 2E }
        $original_file_name = { 4F 00 72 00 69 00 67 00 69 00 6E 00 61 00 6C 00 46 00 69 00 6C 00 65 00 6E 00 61 00 6D 00 65 00 00 00 43 00 6F 00 6D 00 70 00 75 00 74 00 65 00 72 00 5A 00 2E 00 53 00 79 00 73 00 00 00 }
        $version = /V\x00S\x00_\x00V\x00E\x00R\x00S\x00I\x00O\x00N\x00_\x00I\x00N\x00F\x00O\x00\x00\x00{0,4}\xbd\x04\xef\xfe[\x00-\xff]{4}([\x00-\xff][\x00-\xff][\x00-\x00][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\xff][\x00-\xff]|[\x00-\x05][\x00-\x00][\x01-\x01][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\xff][\x00-\xff]|[\x06-\x06][\x00-\x00][\x01-\x01][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\x0a][\x00-\x00]|[\x06-\x06][\x00-\x00][\x01-\x01][\x00-\x00]([\x00-\xff][\x00-\x00]|[\x00-\xff][\x01-\x02]|[\x00-\xef][\x03-\x03])[\x0b-\x0b][\x00-\x00]|[\x06-\x06][\x00-\x00][\x01-\x01][\x00-\x00][\xf0-\xf0][\x03-\x03][\x0b-\x0b][\x00-\x00])/
        $str1 = "ComputerZ.pdb"
        $str2 = "Ludashi System Driver" wide
    condition:
        int16(uint32(0x3C) + 0x5c) == 0x0001 and $subject_name and $original_file_name and $version and $str1 and $str2
}