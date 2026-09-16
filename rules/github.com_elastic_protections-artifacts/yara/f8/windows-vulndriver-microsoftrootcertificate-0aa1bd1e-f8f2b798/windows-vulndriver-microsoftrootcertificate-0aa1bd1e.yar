rule Windows_VulnDriver_MicrosoftRootCertificate_0aa1bd1e {
    meta:
        author = "Elastic Security"
        id = "0aa1bd1e-2ed5-4b3d-a6bf-e5d89306d98e"
        fingerprint = "ec46e98aeafcc52cbc8fb71ab8a698c32c2894bf25971199de4af49264f3f34b"
        creation_date = "2026-05-22"
        last_modified = "2026-07-20"
        description = "Subject: Microsoft Windows Hardware Compatibility Publisher"
        threat_name = "Windows.VulnDriver.MicrosoftRootCertificate"
        reference_sample = "9bb09752cf3a464455422909edef518ac18fe63cf5e1e8d9d6c2e68db62e0c87"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $subject_name = { 06 03 55 04 03 [2] 4D 69 63 72 6F 73 6F 66 74 20 57 69 6E 64 6F 77 73 20 48 61 72 64 77 61 72 65 20 43 6F 6D 70 61 74 69 62 69 6C 69 74 79 20 50 75 62 6C 69 73 68 65 72 }
        $str1 = "FVTProect32.pdb"
    condition:
        int16(uint32(0x3C) + 0x5c) == 0x0001 and $subject_name and $str1
}