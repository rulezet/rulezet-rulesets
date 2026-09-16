rule Windows_Rootkit_RedDriver_d4f2aaba {
    meta:
        author = "Elastic Security"
        id = "d4f2aaba-f4eb-4eb8-bfce-24520da5c23e"
        fingerprint = "f151c9ed6463b5476582f39e4f74b8053057411d954f7d43a9f1cb468a827555"
        creation_date = "2026-07-26"
        last_modified = "2026-08-11"
        description = "Subject: QQ 2062956250, Version: <= 3.0.0.0"
        threat_name = "Windows.Rootkit.RedDriver"
        reference_sample = "55d9a37c73d5543359ee186feb4979ccd84bff0abd997c58790d6d2c21916c29"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $subject_name = { 06 03 55 04 03 [2] 51 51 20 32 30 36 32 39 35 36 32 35 30 }
        $version = /V\x00S\x00_\x00V\x00E\x00R\x00S\x00I\x00O\x00N\x00_\x00I\x00N\x00F\x00O\x00\x00\x00{0,4}\xbd\x04\xef\xfe[\x00-\xff]{4}([\x00-\xff][\x00-\xff][\x00-\x02][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\xff][\x00-\xff]|[\x00-\x00][\x00-\x00][\x03-\x03][\x00-\x00][\x00-\x00][\x00-\x00][\x00-\x00][\x00-\x00])/
        $str1 = "Driver.pdb"
        $str2 = "Low-Level Driver" wide
    condition:
        int16(uint32(0x3C) + 0x5c) == 0x0001 and int16(uint32(0x3C) + 0x18) == 0x020b and $subject_name and $version and $str1 and $str2
}