rule Windows_VulnDriver_HWiNFO_170e8384 {
    meta:
        author = "Elastic Security"
        id = "170e8384-02b8-4ddd-a0a3-f316b2898308"
        fingerprint = "b238f1682a2c1818f3772fa035d4bf6d4675e56c3920cda2b0ecf21dcf652417"
        creation_date = "2026-05-22"
        last_modified = "2026-07-13"
        description = "Subject: REALiX, Version: <= 8.72.0.0"
        threat_name = "Windows.VulnDriver.HWiNFO"
        reference_sample = "33c6c622464f80a8d8017a03ff3aa196840da8bb03bfb5212b51612b5cf953dc"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $subject_name = { 06 03 55 04 03 [2] 52 45 41 4C 69 58 }
        $original_file_name = { 4F 00 72 00 69 00 67 00 69 00 6E 00 61 00 6C 00 46 00 69 00 6C 00 65 00 6E 00 61 00 6D 00 65 00 00 00 48 00 57 00 69 00 4E 00 46 00 4F 00 36 00 34 00 49 00 2E 00 53 00 59 00 53 00 00 00 }
        $version = /V\x00S\x00_\x00V\x00E\x00R\x00S\x00I\x00O\x00N\x00_\x00I\x00N\x00F\x00O\x00\x00\x00{0,4}\xbd\x04\xef\xfe[\x00-\xff]{4}([\x00-\xff][\x00-\xff][\x00-\x07][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\xff][\x00-\xff]|[\x00-\x47][\x00-\x00][\x08-\x08][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\xff][\x00-\xff]|[\x48-\x48][\x00-\x00][\x08-\x08][\x00-\x00][\x00-\x00][\x00-\x00][\x00-\x00][\x00-\x00])/
        $str1 = "HWiNFO32.pdb"
        $str2 = "HWiNFO IA64 Kernel Driver" wide
    condition:
        int16(uint32(0x3C) + 0x5c) == 0x0001 and int16(uint32(0x3C) + 0x18) == 0x020b and $subject_name and $original_file_name and $version and $str1 and $str2
}