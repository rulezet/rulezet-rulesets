rule Windows_VulnDriver_MicrosoftRootCertificate_fb70edf6 {
    meta:
        author = "Elastic Security"
        id = "fb70edf6-cd8a-4838-a74d-16bd33b352f8"
        fingerprint = "3a71b0297f52dbf89fcfe2e9414e268bd5aefeb93731b9d71029c312ef3e8477"
        creation_date = "2026-05-22"
        last_modified = "2026-07-20"
        description = "Subject: Microsoft Windows Hardware Compatibility Publisher"
        threat_name = "Windows.VulnDriver.MicrosoftRootCertificate"
        reference_sample = "16b6be03495a4f4cf394194566bb02061fba2256cc04dcbde5aa6a17e41b7650"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $subject_name = { 06 03 55 04 03 [2] 4D 69 63 72 6F 73 6F 66 74 20 57 69 6E 64 6F 77 73 20 48 61 72 64 77 61 72 65 20 43 6F 6D 70 61 74 69 62 69 6C 69 74 79 20 50 75 62 6C 69 73 68 65 72 }
        $str1 = "netfilterdrv.pdb"
    condition:
        int16(uint32(0x3C) + 0x5c) == 0x0001 and $subject_name and $str1
}