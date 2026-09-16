rule Windows_VulnDriver_Realtek_4de969a0 {
    meta:
        author = "Elastic Security"
        id = "4de969a0-87a6-4bdb-b131-26f8be781388"
        fingerprint = "22bbaa6947684ae30e81cc22598b87528d511ae02615399d44149d901dbb55a2"
        creation_date = "2026-05-22"
        last_modified = "2026-08-11"
        description = "Subject: Realtek Semiconductor Corp, Version: <= 1.2.116.2015"
        threat_name = "Windows.VulnDriver.Realtek"
        reference_sample = "8ef59605ebb2cb259f19aba1a8c122629c224c58e603f270eaa72f516277620c"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $subject_name = { 06 03 55 04 03 [2] 52 65 61 6C 74 65 6B 20 53 65 6D 69 63 6F 6E 64 75 63 74 6F 72 20 43 6F 72 70 }
        $original_file_name = { 4F 00 72 00 69 00 67 00 69 00 6E 00 61 00 6C 00 46 00 69 00 6C 00 65 00 6E 00 61 00 6D 00 65 00 00 00 72 00 74 00 6B 00 69 00 6F 00 36 00 34 00 2E 00 73 00 79 00 73 00 20 00 00 00 }
        $version = /V\x00S\x00_\x00V\x00E\x00R\x00S\x00I\x00O\x00N\x00_\x00I\x00N\x00F\x00O\x00\x00\x00{0,4}\xbd\x04\xef\xfe[\x00-\xff]{4}([\x00-\xff][\x00-\xff][\x00-\x00][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\xff][\x00-\xff]|[\x00-\x01][\x00-\x00][\x01-\x01][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\xff][\x00-\xff]|[\x02-\x02][\x00-\x00][\x01-\x01][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\x73][\x00-\x00]|[\x02-\x02][\x00-\x00][\x01-\x01][\x00-\x00]([\x00-\xff][\x00-\x00]|[\x00-\xff][\x01-\x06]|[\x00-\xde][\x07-\x07])[\x74-\x74][\x00-\x00]|[\x02-\x02][\x00-\x00][\x01-\x01][\x00-\x00][\xdf-\xdf][\x07-\x07][\x74-\x74][\x00-\x00])/
        $str1 = "rtkio64.pdb"
        $str2 = "Realtek IODriver  " wide
        $str3 = "Realtek IODriver" wide
    condition:
        int16(uint32(0x3C) + 0x5c) == 0x0001 and int16(uint32(0x3C) + 0x18) == 0x020b and $subject_name and $original_file_name and $version and $str1 and $str2 and $str3
}