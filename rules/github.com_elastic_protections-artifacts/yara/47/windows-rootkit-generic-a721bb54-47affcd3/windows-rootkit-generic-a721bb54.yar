rule Windows_Rootkit_Generic_a721bb54 {
    meta:
        author = "Elastic Security"
        id = "a721bb54-88fd-4108-bb44-b66faae40b57"
        fingerprint = "18294e2ffe04889ce0e96750405ca39b30267e32cb3001246e1db1c51ecec136"
        creation_date = "2026-07-22"
        last_modified = "2026-08-11"
        description = "Subject: Microsoft Windows Hardware Compatibility Publisher"
        threat_name = "Windows.Rootkit.Generic"
        reference_sample = "c3ea9a13da6f137238b4b912b1f398b8ccfae41ba618993e6cc6c73eb24800db"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $subject_name = { 06 03 55 04 03 [2] 4D 69 63 72 6F 73 6F 66 74 20 57 69 6E 64 6F 77 73 20 48 61 72 64 77 61 72 65 20 43 6F 6D 70 61 74 69 62 69 6C 69 74 79 20 50 75 62 6C 69 73 68 65 72 }
        $str1 = "F:\\Source Codes\\Aspect-Driver-Rewrite\\x64\\Release\\Windows-Memory-Informer.pdb"
        $str2 = "\\Driver\\MouClass" wide
    condition:
        int16(uint32(0x3C) + 0x5c) == 0x0001 and int16(uint32(0x3C) + 0x18) == 0x020b and $subject_name and $str1 and $str2
}