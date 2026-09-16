rule Windows_VulnDriver_HWiNFO_81cd032c {
    meta:
        author = "Elastic Security"
        id = "81cd032c-f998-4968-b8c7-1e596e3bc0b3"
        fingerprint = "23eb2d0260a1e29bfa6f2d67288303e2081c2cbaf0624906758dc0a9e45f6af1"
        creation_date = "2026-05-22"
        last_modified = "2026-07-13"
        description = "Subject: Martin Malik - REALiX, Version: <= 6.70.0.0"
        threat_name = "Windows.VulnDriver.HWiNFO"
        reference_sample = "76af3f9fa111d694e37058606f2636430bdd378c85b94f426fbfcd6666ebe6cc"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $subject_name = { 06 03 55 04 03 [2] 4D 61 72 74 69 6E 20 4D 61 6C 69 6B 20 2D 20 52 45 41 4C 69 58 }
        $original_file_name = { 4F 00 72 00 69 00 67 00 69 00 6E 00 61 00 6C 00 46 00 69 00 6C 00 65 00 6E 00 61 00 6D 00 65 00 00 00 48 00 57 00 69 00 4E 00 46 00 4F 00 33 00 32 00 2E 00 53 00 59 00 53 00 00 00 }
        $version = /V\x00S\x00_\x00V\x00E\x00R\x00S\x00I\x00O\x00N\x00_\x00I\x00N\x00F\x00O\x00\x00\x00{0,4}\xbd\x04\xef\xfe[\x00-\xff]{4}([\x00-\xff][\x00-\xff][\x00-\x05][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\xff][\x00-\xff]|[\x00-\x45][\x00-\x00][\x06-\x06][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\xff][\x00-\xff]|[\x46-\x46][\x00-\x00][\x06-\x06][\x00-\x00][\x00-\x00][\x00-\x00][\x00-\x00][\x00-\x00])/
        $str1 = "HWiNFO32.pdb"
        $str2 = "HWiNFO32 Kernel Driver" wide
    condition:
        int16(uint32(0x3C) + 0x5c) == 0x0001 and int16(uint32(0x3C) + 0x18) == 0x020b and $subject_name and $original_file_name and $version and $str1 and $str2
}