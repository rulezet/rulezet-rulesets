rule Windows_VulnDriver_Intel_9035e9c7 {
    meta:
        author = "Elastic Security"
        id = "9035e9c7-2868-461d-82d1-a6e6fa8025fa"
        fingerprint = "02ece20ed6d623a9745169d7ea0bdc1b4e9ba33bb40f98cc62f6c42089b9b69a"
        creation_date = "2026-05-22"
        last_modified = "2026-07-20"
        description = "Subject: Intel(R) INTELND1617, Version: <= 1.3.2.13"
        threat_name = "Windows.VulnDriver.Intel"
        reference_sample = "5f6547e9823f94c5b94af1fb69a967c4902f72b6e0c783804835e6ce27f887b0"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $subject_name = { 06 03 55 04 03 [2] 49 6E 74 65 6C 28 52 29 20 49 4E 54 45 4C 4E 44 31 36 31 37 }
        $original_file_name = { 4F 00 72 00 69 00 67 00 69 00 6E 00 61 00 6C 00 46 00 69 00 6C 00 65 00 6E 00 61 00 6D 00 65 00 00 00 69 00 51 00 56 00 57 00 36 00 34 00 2E 00 53 00 59 00 53 00 00 00 }
        $version = /V\x00S\x00_\x00V\x00E\x00R\x00S\x00I\x00O\x00N\x00_\x00I\x00N\x00F\x00O\x00\x00\x00{0,4}\xbd\x04\xef\xfe[\x00-\xff]{4}([\x00-\xff][\x00-\xff][\x00-\x00][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\xff][\x00-\xff]|[\x00-\x02][\x00-\x00][\x01-\x01][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\xff][\x00-\xff]|[\x03-\x03][\x00-\x00][\x01-\x01][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\x01][\x00-\x00]|[\x03-\x03][\x00-\x00][\x01-\x01][\x00-\x00][\x00-\x0c][\x00-\x00][\x02-\x02][\x00-\x00]|[\x03-\x03][\x00-\x00][\x01-\x01][\x00-\x00][\x0d-\x0d][\x00-\x00][\x02-\x02][\x00-\x00])/
        $str1 = "iqvw64e.pdb"
        $str2 = "Intel(R) iQVW64.SYS" wide
        $str3 = "Intel(R) Network Adapter Diagnostic Driver" wide
    condition:
        int16(uint32(0x3C) + 0x5c) == 0x0001 and int16(uint32(0x3C) + 0x18) == 0x020b and $subject_name and $original_file_name and $version and $str1 and $str2 and $str3
}