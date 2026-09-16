rule Windows_VulnDriver_Intel_52c8eb58 {
    meta:
        author = "Elastic Security"
        id = "52c8eb58-bc09-4a5b-b5b6-06a26d105028"
        fingerprint = "c938385a273c11d335aafa201d940bfdabebfcca5f6f66ad340afa4756c1b8ad"
        creation_date = "2026-05-22"
        last_modified = "2026-07-20"
        description = "Subject: Intel Corporation - Embedded Subsystems and IP Blocks Group"
        threat_name = "Windows.VulnDriver.Intel"
        reference_sample = "b78eb7f12ba718183313cf336655996756411b7dcc8648157aaa4c891ca9dbee"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $subject_name = { 06 03 55 04 03 [2] 49 6E 74 65 6C 20 43 6F 72 70 6F 72 61 74 69 6F 6E 20 2D 20 45 6D 62 65 64 64 65 64 20 53 75 62 73 79 73 74 65 6D 73 20 61 6E 64 20 49 50 20 42 6C 6F 63 6B 73 20 47 72 6F 75 70 }
        $str1 = "IoAccess.pdb"
    condition:
        int16(uint32(0x3C) + 0x5c) == 0x0001 and $subject_name and $str1
}