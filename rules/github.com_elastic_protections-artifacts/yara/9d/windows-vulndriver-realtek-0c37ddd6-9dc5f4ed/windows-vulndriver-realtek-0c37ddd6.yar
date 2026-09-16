rule Windows_VulnDriver_Realtek_0c37ddd6 {
    meta:
        author = "Elastic Security"
        id = "0c37ddd6-4eb3-41f4-8cc3-2f249f7d0c0e"
        fingerprint = "469ab82f2cc6a36a2aeeff01aa8a8b1f5c78a9dec1488a608b2779a6b35e44e5"
        creation_date = "2026-05-22"
        last_modified = "2026-08-11"
        description = "Subject: Realtek Semiconductor Corp., Version: <= 1.13.0.0"
        threat_name = "Windows.VulnDriver.Realtek"
        reference_sample = "cdf38928a13dfe0e6de054f0229945b9f7db9f88eb7269ecefdceb4b5fab4bfa"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $subject_name = { 06 03 55 04 03 [2] 52 65 61 6C 74 65 6B 20 53 65 6D 69 63 6F 6E 64 75 63 74 6F 72 20 43 6F 72 70 2E }
        $original_file_name = { 4F 00 72 00 69 00 67 00 69 00 6E 00 61 00 6C 00 46 00 69 00 6C 00 65 00 6E 00 61 00 6D 00 65 00 00 00 43 00 6D 00 55 00 70 00 78 00 00 00 }
        $version = /V\x00S\x00_\x00V\x00E\x00R\x00S\x00I\x00O\x00N\x00_\x00I\x00N\x00F\x00O\x00\x00\x00{0,4}\xbd\x04\xef\xfe[\x00-\xff]{4}([\x00-\xff][\x00-\xff][\x00-\x00][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\xff][\x00-\xff]|[\x00-\x0c][\x00-\x00][\x01-\x01][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\xff][\x00-\xff]|[\x0d-\x0d][\x00-\x00][\x01-\x01][\x00-\x00][\x00-\x00][\x00-\x00][\x00-\x00][\x00-\x00])/
        $str1 = "CmUpx.pdb"
        $str2 = "CmUpx driver for Realtek USB device" wide
    condition:
        int16(uint32(0x3C) + 0x5c) == 0x0001 and int16(uint32(0x3C) + 0x18) == 0x020b and $subject_name and $original_file_name and $version and $str1 and $str2
}