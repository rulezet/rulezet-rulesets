rule Windows_VulnDriver_Intel_e36207b2 {
    meta:
        author = "Elastic Security"
        id = "e36207b2-fb3c-4b07-8136-5760d17b21b6"
        fingerprint = "885b7932a11786a4ae8d43ebcb50ab6951a8554d14a8fb7e77b03b2530fc022a"
        creation_date = "2026-05-22"
        last_modified = "2026-07-20"
        description = "Subject: Intel(R) Code Signing External"
        threat_name = "Windows.VulnDriver.Intel"
        reference_sample = "9f1229cd8dd9092c27a01f5d56e3c0d59c2bb9f0139abf042e56f343637fda33"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $subject_name = { 06 03 55 04 03 [2] 49 6E 74 65 6C 28 52 29 20 43 6F 64 65 20 53 69 67 6E 69 6E 67 20 45 78 74 65 72 6E 61 6C }
        $str1 = "semav6msr64.pdb"
        $str2 = "IOCTL_SEMAV6MSR64_CLEAR_ONE"
        $str3 = "IOCTL_SEMAV6MSR64_WRITE_ONE"
    condition:
        int16(uint32(0x3C) + 0x5c) == 0x0001 and int16(uint32(0x3C) + 0x18) == 0x020b and $subject_name and $str1 and $str2 and $str3
}