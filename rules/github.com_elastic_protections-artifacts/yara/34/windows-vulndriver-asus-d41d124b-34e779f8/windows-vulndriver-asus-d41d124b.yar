rule Windows_VulnDriver_Asus_d41d124b {
    meta:
        author = "Elastic Security"
        id = "d41d124b-51d9-4f29-99cf-01512ea74b72"
        fingerprint = "c18520e395f35328e8bfcbbd85842b620c2d83db8d2900fc4676725df506dd5d"
        creation_date = "2026-05-22"
        last_modified = "2026-06-25"
        description = "Subject: ASUSTeK Computer Inc."
        threat_name = "Windows.VulnDriver.Asus"
        reference_sample = "41765151df57125286b398cc107ff8007972f4653527f876d133dac1548865d6"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $subject_name = { 06 03 55 04 03 [2] 41 53 55 53 54 65 4B 20 43 6F 6D 70 75 74 65 72 20 49 6E 63 2E }
        $str1 = "AsIO.pdb"
    condition:
        int16(uint32(0x3C) + 0x5c) == 0x0001 and $subject_name and $str1
}