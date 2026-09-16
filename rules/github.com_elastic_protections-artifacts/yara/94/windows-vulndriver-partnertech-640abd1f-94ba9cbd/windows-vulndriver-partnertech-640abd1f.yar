rule Windows_VulnDriver_PartnerTech_640abd1f {
    meta:
        author = "Elastic Security"
        id = "640abd1f-e732-4d34-9423-41395d181bf3"
        fingerprint = "6ea18b4228672b14430dfa2ab87462fafd4d580e8850e0442bfcafb6927c17c5"
        creation_date = "2026-05-22"
        last_modified = "2026-07-20"
        description = "Subject: Partner Tech(Shanghai)Co.,Ltd"
        threat_name = "Windows.VulnDriver.PartnerTech"
        reference_sample = "dc2b92f59fd8d059a58cc0761212f788d7041f708f4bd717d1738de909b4f781"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $subject_name = { 06 03 55 04 03 [2] 50 61 72 74 6E 65 72 20 54 65 63 68 28 53 68 61 6E 67 68 61 69 29 43 6F 2E 2C 4C 74 64 }
        $str1 = "WinIo.pdb"
        $str2 = "IOCTL_WINIO_UNMAPPHYSADDR"
        $str3 = "IOCTL_WINIO_MAPPHYSTOLIN"
    condition:
        int16(uint32(0x3C) + 0x5c) == 0x0001 and int16(uint32(0x3C) + 0x18) == 0x020b and $subject_name and $str1 and $str2 and $str3
}