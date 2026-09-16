rule Windows_Rootkit_Generic_e4cb3338 {
    meta:
        author = "Elastic Security"
        id = "e4cb3338-7780-45bd-b46c-1a52c325f887"
        fingerprint = "243b30e3142328c210261825b89b4f8fdc5d7cd14709cde7103e6eee2bd845ac"
        creation_date = "2026-07-22"
        last_modified = "2026-08-11"
        description = "Subject: Microsoft Windows Hardware Compatibility Publisher"
        threat_name = "Windows.Rootkit.Generic"
        reference_sample = "1da4f7f001d239a54fab50eb7c3cbc985db392a3d4405e19c3a5d2035d591004"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $subject_name = { 06 03 55 04 03 [2] 4D 69 63 72 6F 73 6F 66 74 20 57 69 6E 64 6F 77 73 20 48 61 72 64 77 61 72 65 20 43 6F 6D 70 61 74 69 62 69 6C 69 74 79 20 50 75 62 6C 69 73 68 65 72 }
        $str1 = "\\DosDevices\\%x" wide
        $seq1 = { 48 89 5C 24 08 57 48 83 EC 20 48 8B 05 87 22 00 00 48 8D 1D 78 22 00 00 48 8B F9 48 8D 0D 5E 22 00 00 48 3B C1 74 45 }
    condition:
        int16(uint32(0x3C) + 0x5c) == 0x0001 and int16(uint32(0x3C) + 0x18) == 0x020b and $subject_name and $str1 and $seq1
}