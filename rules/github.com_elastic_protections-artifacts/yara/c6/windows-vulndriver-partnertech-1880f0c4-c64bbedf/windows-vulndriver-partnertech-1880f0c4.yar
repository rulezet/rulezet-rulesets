rule Windows_VulnDriver_PartnerTech_1880f0c4 {
    meta:
        author = "Elastic Security"
        id = "1880f0c4-8868-4708-bcfd-1e14b89847dd"
        fingerprint = "5af2ce113a4c948aff668f324599508f1150409f604a069008cc205801c5a474"
        creation_date = "2026-05-22"
        last_modified = "2026-07-20"
        description = "Subject: Partner Tech(Shanghai)Co.,Ltd"
        threat_name = "Windows.VulnDriver.PartnerTech"
        reference_sample = "51e280cd9d1d84d43fab4a7be894804f24a1ca4d39f1df16fd8c60ea0a43b786"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $subject_name = { 06 03 55 04 03 [2] 50 61 72 74 6E 65 72 20 54 65 63 68 28 53 68 61 6E 67 68 61 69 29 43 6F 2E 2C 4C 74 64 }
        $str1 = "WinIo.pdb"
        $str2 = "IOCTL_WINIO_DISABLEDIRECTIO"
        $str3 = "IOCTL_WINIO_ENABLEDIRECTIO"
    condition:
        int16(uint32(0x3C) + 0x5c) == 0x0001 and $subject_name and $str1 and $str2 and $str3
}