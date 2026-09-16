rule Windows_VulnDriver_Intel_a465883c {
    meta:
        author = "Elastic Security"
        id = "a465883c-880f-479e-9e8a-a57fb5de2d10"
        fingerprint = "72e4a43423cfc30a92ae7c3a1e00908e29a9f87be78d96210f6299ac397372d6"
        creation_date = "2026-05-22"
        last_modified = "2026-07-20"
        description = "Subject: Intel(R) Tools and Technologies, Version: <= 1.0.1.0"
        threat_name = "Windows.VulnDriver.Intel"
        reference_sample = "70afdc0e11db840d5367afe53c35d9642c1cf616c7832ab283781d085988e505"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $subject_name = { 06 03 55 04 03 [2] 49 6E 74 65 6C 28 52 29 20 54 6F 6F 6C 73 20 61 6E 64 20 54 65 63 68 6E 6F 6C 6F 67 69 65 73 }
        $original_file_name = { 4F 00 72 00 69 00 67 00 69 00 6E 00 61 00 6C 00 46 00 69 00 6C 00 65 00 6E 00 61 00 6D 00 65 00 00 00 73 00 74 00 64 00 63 00 64 00 72 00 76 00 77 00 73 00 36 00 34 00 2E 00 73 00 79 00 73 00 00 00 }
        $version = /V\x00S\x00_\x00V\x00E\x00R\x00S\x00I\x00O\x00N\x00_\x00I\x00N\x00F\x00O\x00\x00\x00{0,4}\xbd\x04\xef\xfe[\x00-\xff]{4}([\x00-\xff][\x00-\xff][\x00-\x00][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\xff][\x00-\xff]|[\x00-\x00][\x00-\x00][\x01-\x01][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\x00][\x00-\x00]|[\x00-\x00][\x00-\x00][\x01-\x01][\x00-\x00][\x00-\x00][\x00-\x00][\x01-\x01][\x00-\x00])/
        $str1 = "stdcdrvws64.pdb"
        $str2 = "SelfTest Data Collector Driver for Windows 7 x64" wide
        $str3 = "SelfTest Data Collector Driver" wide
    condition:
        int16(uint32(0x3C) + 0x5c) == 0x0001 and int16(uint32(0x3C) + 0x18) == 0x020b and $subject_name and $original_file_name and $version and $str1 and $str2 and $str3
}