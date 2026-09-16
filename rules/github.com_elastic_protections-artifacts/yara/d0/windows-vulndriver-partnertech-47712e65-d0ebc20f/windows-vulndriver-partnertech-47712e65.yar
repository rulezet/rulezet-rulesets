rule Windows_VulnDriver_PartnerTech_47712e65 {
    meta:
        author = "Elastic Security"
        id = "47712e65-40b3-41ab-b4e5-81820a155821"
        fingerprint = "8279fcc97c4eec119d8c78ee51d353025a1ed0762f168d1e0384a6c32b101c04"
        creation_date = "2026-05-22"
        last_modified = "2026-07-20"
        description = "Subject: Partner Tech Corporation"
        threat_name = "Windows.VulnDriver.PartnerTech"
        reference_sample = "0a6c37aa1d2d09f45078a22a9603f63dabc3ed33a3e1c27ae0baaa8ba0706757"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $subject_name = { 06 03 55 04 03 [2] 50 61 72 74 6E 65 72 20 54 65 63 68 20 43 6F 72 70 6F 72 61 74 69 6F 6E }
        $str1 = "WinIO64D.pdb"
    condition:
        int16(uint32(0x3C) + 0x5c) == 0x0001 and int16(uint32(0x3C) + 0x18) == 0x020b and $subject_name and $str1
}