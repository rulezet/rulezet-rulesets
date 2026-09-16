rule Windows_VulnDriver_Asus_81ba2bde {
    meta:
        author = "Elastic Security"
        id = "81ba2bde-7ba2-4f26-95c1-f565566848b4"
        fingerprint = "645dd8d992a60fab02e8bc6ccafc569c135d86354398e056ae4967fd77ad0c6d"
        creation_date = "2026-05-22"
        last_modified = "2026-06-25"
        description = "Subject: ASUSTeK Computer Inc."
        threat_name = "Windows.VulnDriver.Asus"
        reference_sample = "38c18db050b0b2b07f657c03db1c9595febae0319c746c3eede677e21cd238b0"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $subject_name = { 06 03 55 04 03 [2] 41 53 55 53 54 65 4B 20 43 6F 6D 70 75 74 65 72 20 49 6E 63 2E }
        $str1 = "Drv.pdb"
        $str2 = "IOCTL_WINIO_UNMAPPHYSADDR"
        $str3 = "IOCTL_WINIO_MAPPHYSTOLIN"
    condition:
        int16(uint32(0x3C) + 0x5c) == 0x0001 and int16(uint32(0x3C) + 0x18) == 0x020b and $subject_name and $str1 and $str2 and $str3
}