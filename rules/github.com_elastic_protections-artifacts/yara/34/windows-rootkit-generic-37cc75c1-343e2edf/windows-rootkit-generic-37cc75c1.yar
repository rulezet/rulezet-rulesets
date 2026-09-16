rule Windows_Rootkit_Generic_37cc75c1 {
    meta:
        author = "Elastic Security"
        id = "37cc75c1-fa15-4009-821d-ba5ab493f61a"
        fingerprint = "12869f993b9a65b5e32b954db873738afa7b4b0aba3a87a178e78b92c7a66a39"
        creation_date = "2026-07-22"
        last_modified = "2026-08-11"
        description = "Subject: FEI XIAO, Version: <= 1.0.0.1"
        threat_name = "Windows.Rootkit.Generic"
        reference_sample = "c619a7fbb27940428b80129e0fa2d976fce52f93ab37667d2ca01330c6c561a5"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $subject_name = { 06 03 55 04 03 [2] 46 45 49 20 58 49 41 4F }
        $version = /V\x00S\x00_\x00V\x00E\x00R\x00S\x00I\x00O\x00N\x00_\x00I\x00N\x00F\x00O\x00\x00\x00{0,4}\xbd\x04\xef\xfe[\x00-\xff]{4}([\x00-\xff][\x00-\xff][\x00-\x00][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\xff][\x00-\xff]|[\x00-\x00][\x00-\x00][\x01-\x01][\x00-\x00][\x00-\x00][\x00-\x00][\x00-\x00][\x00-\x00]|[\x00-\x00][\x00-\x00][\x01-\x01][\x00-\x00][\x01-\x01][\x00-\x00][\x00-\x00][\x00-\x00])/
        $str1 = "HalMakeBeep"
        $seq1 = { 51 F6 D6 F8 66 D3 C2 53 48 31 E3 48 0F B3 C3 48 89 C3 C0 DE 03 D2 C2 66 0F BB E2 F5 BA 01 00 00 00 48 0F BA E0 21 83 F9 07 }
    condition:
        int16(uint32(0x3C) + 0x5c) == 0x0001 and int16(uint32(0x3C) + 0x18) == 0x020b and $subject_name and $version and $str1 and $seq1
}