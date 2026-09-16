rule Windows_VulnDriver_K7RKScan_5961a62d {
    meta:
        author = "Elastic Security"
        id = "5961a62d-fe45-4f64-b2c1-bce314128a15"
        fingerprint = "2b629e57ecf515c1ed002ce51e96e9e19c98430580f84fa84978bf4e2cc755f7"
        creation_date = "2026-05-22"
        last_modified = "2026-07-20"
        description = "Subject: Microsoft Windows Hardware Compatibility Publisher, Version: <= 23.0.0.10"
        threat_name = "Windows.VulnDriver.K7RKScan"
        reference_sample = "1ad0c870620b8a749217600c8f68558da355e1ba0a8e91cb758d8418beb13196"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $subject_name = { 06 03 55 04 03 [2] 4D 69 63 72 6F 73 6F 66 74 20 57 69 6E 64 6F 77 73 20 48 61 72 64 77 61 72 65 20 43 6F 6D 70 61 74 69 62 69 6C 69 74 79 20 50 75 62 6C 69 73 68 65 72 }
        $original_file_name = { 4F 00 72 00 69 00 67 00 69 00 6E 00 61 00 6C 00 46 00 69 00 6C 00 65 00 6E 00 61 00 6D 00 65 00 00 00 4B 00 37 00 52 00 4B 00 53 00 63 00 61 00 6E 00 00 00 }
        $version = /V\x00S\x00_\x00V\x00E\x00R\x00S\x00I\x00O\x00N\x00_\x00I\x00N\x00F\x00O\x00\x00\x00{0,4}\xbd\x04\xef\xfe[\x00-\xff]{4}([\x00-\xff][\x00-\xff][\x00-\x16][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\xff][\x00-\xff]|[\x00-\x00][\x00-\x00][\x17-\x17][\x00-\x00][\x00-\x09][\x00-\x00][\x00-\x00][\x00-\x00]|[\x00-\x00][\x00-\x00][\x17-\x17][\x00-\x00][\x0a-\x0a][\x00-\x00][\x00-\x00][\x00-\x00])/
        $str1 = "K7RKScan.pdb"
        $str2 = "K7RKScan" wide
        $str3 = "K7RKScan Kernel Module" wide
    condition:
        int16(uint32(0x3C) + 0x5c) == 0x0001 and int16(uint32(0x3C) + 0x18) == 0x020b and $subject_name and $original_file_name and $version and $str1 and $str2 and $str3
}