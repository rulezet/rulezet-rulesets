rule Windows_VulnDriver_Asus_998862dc {
    meta:
        author = "Elastic Security"
        id = "998862dc-d96c-4013-a8de-99e7cbe8649f"
        fingerprint = "5aed9446e0198c3d94518ee996e03e3d6fc4c56a850d540c05c6de321b160709"
        creation_date = "2026-05-22"
        last_modified = "2026-06-25"
        description = "Subject: ASUSTeK Computer Inc."
        threat_name = "Windows.VulnDriver.Asus"
        reference_sample = "13ae4d9dcacba8133d8189e59d9352272e15629e6bca580c32aff9810bd96e44"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $subject_name = { 06 03 55 04 03 [2] 41 53 55 53 54 65 4B 20 43 6F 6D 70 75 74 65 72 20 49 6E 63 2E }
        $str1 = "TdeIo64.pdb"
        $str2 = "IOCTL_INDEXIO_WRITE_DWORD"
        $str3 = "IOCTL_INDEXIO_READ_DWORD"
    condition:
        int16(uint32(0x3C) + 0x5c) == 0x0001 and int16(uint32(0x3C) + 0x18) == 0x020b and $subject_name and $str1 and $str2 and $str3
}