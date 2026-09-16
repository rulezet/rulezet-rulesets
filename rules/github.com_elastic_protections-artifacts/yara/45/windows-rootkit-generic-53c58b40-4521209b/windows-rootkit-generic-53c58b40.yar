rule Windows_Rootkit_Generic_53c58b40 {
    meta:
        author = "Elastic Security"
        id = "53c58b40-b1bf-4db7-bd80-4d6f86dd06a1"
        fingerprint = "7c12b3c93ffb4bb7e4173e77e1c716aa91914377befcf403960b63fbb95ca911"
        creation_date = "2026-07-21"
        last_modified = "2026-08-11"
        description = "Subject: Microsoft Windows Hardware Compatibility Publisher"
        threat_name = "Windows.Rootkit.Generic"
        reference_sample = "412564937dea61ad443a3f50a0f7586aed1bf68795e9af184606804357499cea"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $subject_name = { 06 03 55 04 03 [2] 4D 69 63 72 6F 73 6F 66 74 20 57 69 6E 64 6F 77 73 20 48 61 72 64 77 61 72 65 20 43 6F 6D 70 61 74 69 62 69 6C 69 74 79 20 50 75 62 6C 69 73 68 65 72 }
        $str1 = "D:\\projects\\memdrv\\build\\x64\\Release\\memdrv.pdb"
        $str2 = "\\Device\\Redirt" wide
        $seq1 = { 41 8B C0 2D 0C A0 22 00 74 61 83 E8 04 74 55 83 E8 14 74 49 2D DC 3F 00 00 74 25 83 F8 20 74 16 }
    condition:
        int16(uint32(0x3C) + 0x5c) == 0x0001 and int16(uint32(0x3C) + 0x18) == 0x020b and $subject_name and $str1 and $str2 and $seq1
}