rule Windows_VulnDriver_Wistron_99bd2c09 {
    meta:
        author = "Elastic Security"
        id = "99bd2c09-8074-4d98-8dee-cac58c3aa5a6"
        fingerprint = "a0ebf678ca8c5d97e8752a07a03171047c655aeae9f34cea17fa9ed428b841fc"
        creation_date = "2026-05-22"
        last_modified = "2026-07-29"
        description = "Subject: Wistron Corporation"
        threat_name = "Windows.VulnDriver.Wistron"
        reference_sample = "4c776f34c6042d943baec3c13d7154a245aae8dd95e1933211fd19352c770676"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $subject_name = { 06 03 55 04 03 [2] 57 69 73 74 72 6F 6E 20 43 6F 72 70 6F 72 61 74 69 6F 6E }
        $str1 = "Access.pdb"
    condition:
        int16(uint32(0x3C) + 0x5c) == 0x0001 and int16(uint32(0x3C) + 0x18) == 0x020b and $subject_name and $str1
}