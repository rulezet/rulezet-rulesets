rule Windows_VulnDriver_KExplore_30925683 {
    meta:
        author = "Elastic Security"
        id = "30925683-a7d5-421f-bff7-5dd622356214"
        fingerprint = "7f5cb698a40b99f50f4246c61d47a1c6e99fd0c4baa830a7b6a514e567aafe7d"
        creation_date = "2026-05-22"
        last_modified = "2026-06-24"
        description = "Subject: Pavel Yosifovich"
        threat_name = "Windows.VulnDriver.KExplore"
        reference_sample = "5c237dcec01f5e31a78cf8c883e41d85c74675b1426379302b46b771d091dce6"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $subject_name = { 06 03 55 04 03 [2] 50 61 76 65 6C 20 59 6F 73 69 66 6F 76 69 63 68 }
        $str1 = "KRegExp.pdb"
    condition:
        int16(uint32(0x3C) + 0x5c) == 0x0001 and int16(uint32(0x3C) + 0x18) == 0x020b and $subject_name and $str1
}