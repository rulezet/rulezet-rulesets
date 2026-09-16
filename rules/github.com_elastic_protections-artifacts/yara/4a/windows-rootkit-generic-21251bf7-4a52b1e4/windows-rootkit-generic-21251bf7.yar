rule Windows_Rootkit_Generic_21251bf7 {
    meta:
        author = "Elastic Security"
        id = "21251bf7-51ae-4c98-ab1e-17c1179c0e1f"
        fingerprint = "b055b3287deea2094e14bca15acf206c23406f8423915a5abcac3a3dc215e735"
        creation_date = "2026-07-26"
        last_modified = "2026-08-11"
        description = "Subject: Microsoft Windows Hardware Compatibility Publisher"
        threat_name = "Windows.Rootkit.Generic"
        reference_sample = "f461414a2596555cece5cfee65a3c22648db0082ca211f6238af8230e41b3212"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $subject_name = { 06 03 55 04 03 [2] 4D 69 63 72 6F 73 6F 66 74 20 57 69 6E 64 6F 77 73 20 48 61 72 64 77 61 72 65 20 43 6F 6D 70 61 74 69 62 69 6C 69 74 79 20 50 75 62 6C 69 73 68 65 72 }
        $str1 = "INT-Base10.pdb"
    condition:
        int16(uint32(0x3C) + 0x5c) == 0x0001 and int16(uint32(0x3C) + 0x18) == 0x020b and $subject_name and $str1
}