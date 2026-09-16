rule Windows_VulnDriver_Intel_1abb0887 {
    meta:
        author = "Elastic Security"
        id = "1abb0887-add0-48b3-ad69-8c2a98a3edea"
        fingerprint = "eeeebc2584661e208bbed65f0e036988cb4763ba6a1126e1b5a7948518bf062f"
        creation_date = "2026-05-22"
        last_modified = "2026-07-20"
        description = "Subject: Intel Corporation, Version: <= 6.5.1.31"
        threat_name = "Windows.VulnDriver.Intel"
        reference_sample = "b936c4ba80ccee3b0b3b67fc88c8caa103fcfc47888e976f6d5b6f113d22f41f"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $subject_name = { 06 03 55 04 03 [2] 49 6E 74 65 6C 20 43 6F 72 70 6F 72 61 74 69 6F 6E }
        $original_file_name = { 4F 00 72 00 69 00 67 00 69 00 6E 00 61 00 6C 00 46 00 69 00 6C 00 65 00 6E 00 61 00 6D 00 65 00 00 00 69 00 4F 00 43 00 64 00 72 00 76 00 2E 00 73 00 79 00 73 00 00 00 }
        $version = /V\x00S\x00_\x00V\x00E\x00R\x00S\x00I\x00O\x00N\x00_\x00I\x00N\x00F\x00O\x00\x00\x00{0,4}\xbd\x04\xef\xfe[\x00-\xff]{4}([\x00-\xff][\x00-\xff][\x00-\x05][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\xff][\x00-\xff]|[\x00-\x04][\x00-\x00][\x06-\x06][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\xff][\x00-\xff]|[\x05-\x05][\x00-\x00][\x06-\x06][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\x00][\x00-\x00]|[\x05-\x05][\x00-\x00][\x06-\x06][\x00-\x00][\x00-\x1e][\x00-\x00][\x01-\x01][\x00-\x00]|[\x05-\x05][\x00-\x00][\x06-\x06][\x00-\x00][\x1f-\x1f][\x00-\x00][\x01-\x01][\x00-\x00])/
        $str1 = "iocbios2.pdb"
        $str2 = "Intel(R) Extreme Tuning Utility" wide
        $str3 = "Intel(R) Overclocking Device Driver" wide
    condition:
        int16(uint32(0x3C) + 0x5c) == 0x0001 and int16(uint32(0x3C) + 0x18) == 0x020b and $subject_name and $original_file_name and $version and $str1 and $str2 and $str3
}