rule Windows_VulnDriver_Asus_58d896dc {
    meta:
        author = "Elastic Security"
        id = "58d896dc-dae9-4689-9688-53cbd02a725b"
        fingerprint = "51ca96ffaae4d15369c47be928cb0b1fb26cde7c6e0aa305ba7e461e516d5a61"
        creation_date = "2026-05-22"
        last_modified = "2026-06-25"
        description = "Subject: ASUSTeK Computer Inc."
        threat_name = "Windows.VulnDriver.Asus"
        reference_sample = "26453afb1f808f64bec87a2532a9361b696c0ed501d6b973a1f1b5ae152a4d40"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $subject_name = { 06 03 55 04 03 [2] 41 53 55 53 54 65 4B 20 43 6F 6D 70 75 74 65 72 20 49 6E 63 2E }
        $str1 = "AsIO3_64.pdb"
    condition:
        int16(uint32(0x3C) + 0x5c) == 0x0001 and int16(uint32(0x3C) + 0x18) == 0x020b and $subject_name and $str1
}