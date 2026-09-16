rule Windows_VulnDriver_Asus_f2e2b71a {
    meta:
        author = "Elastic Security"
        id = "f2e2b71a-6fd9-4d99-85c0-78610a3d1248"
        fingerprint = "c0460f0545a62abc39ed0dfb7425584922c19d2a02f3caf13167a39f24105881"
        creation_date = "2026-05-22"
        last_modified = "2026-06-25"
        description = "Subject: ASUSTeK COMPUTER INC., Version: <= 2.5.0.0"
        threat_name = "Windows.VulnDriver.Asus"
        reference_sample = "e62d0c1353a3d913497e6016d0f48d7cf9ef99e4026b94ccd873d6c7a9a54565"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $subject_name = { 06 03 55 04 03 [2] 41 53 55 53 54 65 4B 20 43 4F 4D 50 55 54 45 52 20 49 4E 43 2E }
        $original_file_name = { 4F 00 72 00 69 00 67 00 69 00 6E 00 61 00 6C 00 46 00 69 00 6C 00 65 00 6E 00 61 00 6D 00 65 00 00 00 49 00 4F 00 4D 00 61 00 70 00 2E 00 73 00 79 00 73 00 00 00 }
        $version = /V\x00S\x00_\x00V\x00E\x00R\x00S\x00I\x00O\x00N\x00_\x00I\x00N\x00F\x00O\x00\x00\x00{0,4}\xbd\x04\xef\xfe[\x00-\xff]{4}([\x00-\xff][\x00-\xff][\x00-\x01][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\xff][\x00-\xff]|[\x00-\x04][\x00-\x00][\x02-\x02][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\xff][\x00-\xff]|[\x05-\x05][\x00-\x00][\x02-\x02][\x00-\x00][\x00-\x00][\x00-\x00][\x00-\x00][\x00-\x00])/
        $str1 = "IOMap.pdb"
        $str2 = "ASUS Kernel Mode Driver for Windows" wide
        $str3 = "ASUS Kernel Mode Driver for NT " wide
    condition:
        int16(uint32(0x3C) + 0x5c) == 0x0001 and int16(uint32(0x3C) + 0x18) == 0x020b and $subject_name and $original_file_name and $version and $str1 and $str2 and $str3
}