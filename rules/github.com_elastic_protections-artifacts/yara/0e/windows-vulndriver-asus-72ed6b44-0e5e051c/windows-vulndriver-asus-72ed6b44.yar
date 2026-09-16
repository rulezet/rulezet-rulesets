rule Windows_VulnDriver_Asus_72ed6b44 {
    meta:
        author = "Elastic Security"
        id = "72ed6b44-ca6b-4e09-8bcd-e26bee804a40"
        fingerprint = "799bbd30cf1936d446c9140ff018c5e550e3974b1504ffa5f56c1834561e281b"
        creation_date = "2026-05-22"
        last_modified = "2026-06-25"
        description = "Subject: ASUSTeK Computer Inc."
        threat_name = "Windows.VulnDriver.Asus"
        reference_sample = "a7860e110f7a292d621006b7208a634504fb5be417fd71e219060381b9a891e6"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $subject_name = { 06 03 55 04 03 [2] 41 53 55 53 54 65 4B 20 43 6F 6D 70 75 74 65 72 20 49 6E 63 2E }
        $str1 = "AsIO2_64.pdb"
    condition:
        int16(uint32(0x3C) + 0x5c) == 0x0001 and int16(uint32(0x3C) + 0x18) == 0x020b and $subject_name and $str1
}