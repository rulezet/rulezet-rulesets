rule Windows_VulnDriver_PassMark_183dd481 {
    meta:
        author = "Elastic Security"
        id = "183dd481-7052-4a19-aa58-1412e29a0928"
        fingerprint = "46509d10166ce40a7231c6ab6a309fb46682a97e768c7cda44007f3ebf0dd339"
        creation_date = "2026-05-22"
        last_modified = "2026-07-20"
        description = "Subject: PassMark Software Pty Ltd"
        threat_name = "Windows.VulnDriver.PassMark"
        reference_sample = "31f4140c12ac31f5729a8de4dc051d3acd07783564604df831a2a6722c979192"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $subject_name = { 06 03 55 04 03 [2] 50 61 73 73 4D 61 72 6B 20 53 6F 66 74 77 61 72 65 20 50 74 79 20 4C 74 64 }
        $str1 = "DirectIo.pdb"
    condition:
        int16(uint32(0x3C) + 0x5c) == 0x0001 and $subject_name and $str1
}