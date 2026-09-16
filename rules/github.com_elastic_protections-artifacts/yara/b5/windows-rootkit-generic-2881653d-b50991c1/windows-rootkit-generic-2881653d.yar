rule Windows_Rootkit_Generic_2881653d {
    meta:
        author = "Elastic Security"
        id = "2881653d-600f-48d3-be76-cae9f911d8b9"
        fingerprint = "d186030d0d42619efd9fda9a1b22ad2d26f1de8e724337a1b62419beb51732cd"
        creation_date = "2026-07-23"
        last_modified = "2026-08-11"
        description = "Subject: Microsoft Windows Hardware Compatibility Publisher"
        threat_name = "Windows.Rootkit.Generic"
        reference_sample = "ede9a3858a12d5ddea21a310e5721bf86c2248539f42c9e0c3c29ae5b0148ba5"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $subject_name = { 06 03 55 04 03 [2] 4D 69 63 72 6F 73 6F 66 74 20 57 69 6E 64 6F 77 73 20 48 61 72 64 77 61 72 65 20 43 6F 6D 70 61 74 69 62 69 6C 69 74 79 20 50 75 62 6C 69 73 68 65 72 }
        $str1 = "e:\\repos\\pcm\\winmsrdriver\\win7\\objfre_win7_amd64\\amd64\\msr.pdb"
        $seq1 = { 48 89 5C 24 08 48 89 74 24 18 57 48 83 EC 60 48 8B 05 76 E0 FF FF 48 33 C4 48 89 44 24 58 48 8B 8A B8 00 00 00 33 DB 48 8B FA 48 3B CB 0F 84 DD 01 00 00 }
    condition:
        int16(uint32(0x3C) + 0x5c) == 0x0001 and int16(uint32(0x3C) + 0x18) == 0x020b and $subject_name and $str1 and $seq1
}