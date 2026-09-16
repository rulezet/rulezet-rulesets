rule Windows_VulnDriver_Intel_221a6d31 {
    meta:
        author = "Elastic Security"
        id = "221a6d31-1fab-4c62-aa02-8c119a1061a4"
        fingerprint = "58a6c7f39035be7b5d37217bb70bf984ab7fee9407f8b307fb1a6a133242fe3e"
        creation_date = "2026-05-22"
        last_modified = "2026-07-20"
        description = "Subject: Intel(R) Tools and Technologies, Version: <= 1.0.1.0"
        threat_name = "Windows.VulnDriver.Intel"
        reference_sample = "3a2453ac5288505187d8dae35234ff2b0883f5d681146218ee4a2d7d6d8cddaf"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $subject_name = { 06 03 55 04 03 [2] 49 6E 74 65 6C 28 52 29 20 54 6F 6F 6C 73 20 61 6E 64 20 54 65 63 68 6E 6F 6C 6F 67 69 65 73 }
        $original_file_name = { 4F 00 72 00 69 00 67 00 69 00 6E 00 61 00 6C 00 46 00 69 00 6C 00 65 00 6E 00 61 00 6D 00 65 00 00 00 73 00 74 00 64 00 63 00 64 00 72 00 76 00 78 00 70 00 36 00 34 00 2E 00 73 00 79 00 73 00 00 00 }
        $version = /V\x00S\x00_\x00V\x00E\x00R\x00S\x00I\x00O\x00N\x00_\x00I\x00N\x00F\x00O\x00\x00\x00{0,4}\xbd\x04\xef\xfe[\x00-\xff]{4}([\x00-\xff][\x00-\xff][\x00-\x00][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\xff][\x00-\xff]|[\x00-\x00][\x00-\x00][\x01-\x01][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\x00][\x00-\x00]|[\x00-\x00][\x00-\x00][\x01-\x01][\x00-\x00][\x00-\x00][\x00-\x00][\x01-\x01][\x00-\x00])/
        $str1 = "stdcdrvxp64.pdb"
        $str2 = "SelfTest Data Collector Driver for Windows x64" wide
        $str3 = "SelfTest Data Collector Driver" wide
    condition:
        int16(uint32(0x3C) + 0x5c) == 0x0001 and int16(uint32(0x3C) + 0x18) == 0x020b and $subject_name and $original_file_name and $version and $str1 and $str2 and $str3
}