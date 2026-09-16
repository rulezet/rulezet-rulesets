rule Windows_VulnDriver_PassMark_1ff60e4b {
    meta:
        author = "Elastic Security"
        id = "1ff60e4b-001f-42a6-bbb9-cbdbe0dece1e"
        fingerprint = "0cb391e8be4046c1b2cefea60468e304e67b643e87b210c1f0e599fb75f0dbcf"
        creation_date = "2026-05-22"
        last_modified = "2026-07-20"
        description = "Subject: PassMark Software Pty Ltd"
        threat_name = "Windows.VulnDriver.PassMark"
        reference_sample = "8939116df1d6c8fd0ebd14b2d37b3dec38a8820aa666ecd487bc1bb794f2a587"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $subject_name = { 06 03 55 04 03 [2] 50 61 73 73 4D 61 72 6B 20 53 6F 66 74 77 61 72 65 20 50 74 79 20 4C 74 64 }
        $str1 = "DirectIo64.pdb"
    condition:
        int16(uint32(0x3C) + 0x5c) == 0x0001 and int16(uint32(0x3C) + 0x18) == 0x020b and $subject_name and $str1
}