rule Windows_VulnDriver_Asus_1970c0aa {
    meta:
        author = "Elastic Security"
        id = "1970c0aa-c445-42a4-ad54-2bfe0c1bb6f2"
        fingerprint = "bed82c63f4d8ce42b1f2aa0e9b8f027359d93c8066fbe8b3d6509133260a6fb2"
        creation_date = "2026-05-22"
        last_modified = "2026-06-25"
        description = "Subject: ASUSTeK Computer Inc."
        threat_name = "Windows.VulnDriver.Asus"
        reference_sample = "b4d47ea790920a4531e3df5a4b4b0721b7fea6b49a35679f0652f1e590422602"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $subject_name = { 06 03 55 04 03 [2] 41 53 55 53 54 65 4B 20 43 6F 6D 70 75 74 65 72 20 49 6E 63 2E }
        $str1 = "AsUpIO.pdb"
    condition:
        int16(uint32(0x3C) + 0x5c) == 0x0001 and int16(uint32(0x3C) + 0x18) == 0x020b and $subject_name and $str1
}