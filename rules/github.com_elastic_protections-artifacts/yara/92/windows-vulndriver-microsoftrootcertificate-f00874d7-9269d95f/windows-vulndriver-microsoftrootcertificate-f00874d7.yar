rule Windows_VulnDriver_MicrosoftRootCertificate_f00874d7 {
    meta:
        author = "Elastic Security"
        id = "f00874d7-c072-495c-8e7f-c2ca5813ceab"
        fingerprint = "f951371a4a83508ead8f86c3bc9c5418ebe4ad3a946a56849d5991d786da9388"
        creation_date = "2026-05-22"
        last_modified = "2026-07-20"
        description = "Subject: Microsoft Windows"
        threat_name = "Windows.VulnDriver.MicrosoftRootCertificate"
        reference_sample = "6071db01b50c658cf78665c24f1d21f21b4a12d16bfcfaa6813bf6bbc4d0a1e8"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $subject_name = { 06 03 55 04 03 [2] 4D 69 63 72 6F 73 6F 66 74 20 57 69 6E 64 6F 77 73 }
        $str1 = "VBoxDrv.pdb"
        $str2 = "IOCTL_PAGE_ALLOC_SIZE_IN"
        $str3 = "IOCTL_LOW_ALLOC_SIZE_IN"
        $str4 = "RTLogSetDefaultInstanceThread"
        $str5 = "RTSemEventMultiWaitNoResume"
    condition:
        int16(uint32(0x3C) + 0x5c) == 0x0001 and int16(uint32(0x3C) + 0x18) == 0x020b and $subject_name and $str1 and $str2 and $str3 and $str4 and $str5
}