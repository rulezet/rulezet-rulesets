rule Windows_VulnDriver_Intel_1373ed9e {
    meta:
        author = "Elastic Security"
        id = "1373ed9e-2f8e-4a99-bf4f-0bf6d81294fe"
        fingerprint = "69df99c02d8185cc98ab6576a4c14c20c7a8589a2082bff3ad498fe835311e9d"
        creation_date = "2026-05-22"
        last_modified = "2026-07-20"
        description = "Subject: Intel Corporation"
        threat_name = "Windows.VulnDriver.Intel"
        reference_sample = "382cb4c37fdcb2e2ca9cbb4a5de39fa4e230d1d2e1b6f38e1c8249002525f1c7"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $subject_name = { 06 03 55 04 03 [2] 49 6E 74 65 6C 20 43 6F 72 70 6F 72 61 74 69 6F 6E }
        $str1 = "EnergyDriver.pdb"
    condition:
        int16(uint32(0x3C) + 0x5c) == 0x0001 and int16(uint32(0x3C) + 0x18) == 0x020b and $subject_name and $str1
}