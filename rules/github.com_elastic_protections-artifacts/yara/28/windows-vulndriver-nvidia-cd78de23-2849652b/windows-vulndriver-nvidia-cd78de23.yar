rule Windows_VulnDriver_Nvidia_cd78de23 {
    meta:
        author = "Elastic Security"
        id = "cd78de23-7b85-4e23-8b61-a0df6dfa7d68"
        fingerprint = "1c8f034cdb044f2fd22f60f1e22a343745ca14476cf84152064919668b6e0ac7"
        creation_date = "2026-05-22"
        last_modified = "2026-07-20"
        description = "Subject: NVIDIA Corporation"
        threat_name = "Windows.VulnDriver.Nvidia"
        reference_sample = "d7c81b0f3c14844f6424e8bdd31a128e773cb96cccef6d05cbff473f0ccb9f9c"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $subject_name = { 06 03 55 04 03 [2] 4E 56 49 44 49 41 20 43 6F 72 70 6F 72 61 74 69 6F 6E }
        $str1 = "KApcHelper.pdb"
    condition:
        int16(uint32(0x3C) + 0x5c) == 0x0001 and int16(uint32(0x3C) + 0x18) == 0x020b and $subject_name and $str1
}