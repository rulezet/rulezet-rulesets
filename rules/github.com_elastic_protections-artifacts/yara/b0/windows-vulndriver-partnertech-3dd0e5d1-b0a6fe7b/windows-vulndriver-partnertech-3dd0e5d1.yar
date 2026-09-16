rule Windows_VulnDriver_PartnerTech_3dd0e5d1 {
    meta:
        author = "Elastic Security"
        id = "3dd0e5d1-3779-4821-8301-818a6000dde8"
        fingerprint = "33dd35c1a53e36135caba0c493f5da090bc2b26d96ec686bd3fc160812d6b98a"
        creation_date = "2026-05-22"
        last_modified = "2026-07-20"
        description = "Subject: Partner Tech(Shanghai)Co.,Ltd"
        threat_name = "Windows.VulnDriver.PartnerTech"
        reference_sample = "3c9b6da610e409f92f4f95f6f3f92a6e60e24903298a0e9af508f28e8c8962b6"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $subject_name = { 06 03 55 04 03 [2] 50 61 72 74 6E 65 72 20 54 65 63 68 28 53 68 61 6E 67 68 61 69 29 43 6F 2E 2C 4C 74 64 }
        $str1 = "WINIODrv.pdb"
    condition:
        int16(uint32(0x3C) + 0x5c) == 0x0001 and $subject_name and $str1
}