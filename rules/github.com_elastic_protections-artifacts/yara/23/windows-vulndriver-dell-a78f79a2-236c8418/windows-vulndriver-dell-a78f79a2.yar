rule Windows_VulnDriver_Dell_a78f79a2 {
    meta:
        author = "Elastic Security"
        id = "a78f79a2-6aed-4c29-8dcd-c65bb75ed4fd"
        fingerprint = "d1ee5951e1056ab8bb950023a064855cf50341e4612617c53e746770eb0a259d"
        creation_date = "2026-07-26"
        last_modified = "2026-08-11"
        description = "Subject: Dell Inc."
        threat_name = "Windows.VulnDriver.Dell"
        reference_sample = "0684e092f2b9d516d190f9c62ce83239b623ea44518ad425906f3059a885dbc3"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $subject_name = { 06 03 55 04 03 [2] 44 65 6C 6C 20 49 6E 63 2E }
        $str1 = "DBDrvr64.pdb"
        $seq1 = { 67 24 DC 31 AC F4 25 E3 6B 4C 14 73 24 B0 C1 C8 B7 EC 07 AE 6F 06 AA 3E A0 88 96 A1 4C CA 3D AE CA DF 31 01 51 D6 A5 B5 E9 91 DF CA 8D 17 31 2F 6D AA 6A C6 4B C3 40 F4 72 A2 85 53 8F 8B 71 69 12 5F D2 40 ED 0E B3 27 06 92 3B E2 79 B2 37 9D AC 17 4A 6D 51 D0 C7 60 53 1C C5 91 3D 61 21 6D 41 A3 19 8A 58 B4 34 27 91 47 1F 50 F3 E6 67 A0 E9 5E 46 E1 C1 EE C5 53 1E BD A1 F6 05 A5 64 EE 14 E1 04 DE C1 5D AF 37 20 1A 34 9D 5C D5 5D 92 E5 86 67 77 2D 00 EE A7 C8 5B 54 69 2B E1 46 99 A6 82 26 76 B1 61 }
    condition:
        int16(uint32(0x3C) + 0x5c) == 0x0001 and int16(uint32(0x3C) + 0x18) == 0x020b and $subject_name and $str1 and $seq1
}