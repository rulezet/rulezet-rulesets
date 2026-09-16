rule Windows_VulnDriver_Asus_f9ef4fe1 {
    meta:
        author = "Elastic Security"
        id = "f9ef4fe1-1caf-4200-8c52-f0c812ad2411"
        fingerprint = "9be8864dd319e091d008d448e6bb6edd5638f7d63a7e8044787832f2c9f02edc"
        creation_date = "2026-05-22"
        last_modified = "2026-06-25"
        description = "Subject: ASUSTeK Computer Inc."
        threat_name = "Windows.VulnDriver.Asus"
        reference_sample = "72322fa8bba20df6966acbcf41e83747893fd173cd29de99b5ad1a5d3bf8f2de"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $subject_name = { 06 03 55 04 03 [2] 41 53 55 53 54 65 4B 20 43 6F 6D 70 75 74 65 72 20 49 6E 63 2E }
        $str1 = "Asushwio2.pdb"
    condition:
        int16(uint32(0x3C) + 0x5c) == 0x0001 and int16(uint32(0x3C) + 0x18) == 0x020b and $subject_name and $str1
}