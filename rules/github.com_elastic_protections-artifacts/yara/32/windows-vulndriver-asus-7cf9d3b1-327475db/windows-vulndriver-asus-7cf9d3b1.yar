rule Windows_VulnDriver_Asus_7cf9d3b1 {
    meta:
        author = "Elastic Security"
        id = "7cf9d3b1-cdf9-4af1-98eb-ab8703b3731a"
        fingerprint = "1d1a2163ea510dd082a9c647c4b9d1c009f3c8b31d2147446f4cd242b6e7dfcd"
        creation_date = "2026-05-22"
        last_modified = "2026-06-25"
        description = "Subject: ASUSTeK Computer Inc."
        threat_name = "Windows.VulnDriver.Asus"
        reference_sample = "03a1e1037ea162020e75e37be771f620c4569e9621175f672583705f3ab569f7"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $subject_name = { 06 03 55 04 03 [2] 41 53 55 53 54 65 4B 20 43 6F 6D 70 75 74 65 72 20 49 6E 63 2E }
        $str1 = "AsIO3_32.pdb"
    condition:
        int16(uint32(0x3C) + 0x5c) == 0x0001 and $subject_name and $str1
}