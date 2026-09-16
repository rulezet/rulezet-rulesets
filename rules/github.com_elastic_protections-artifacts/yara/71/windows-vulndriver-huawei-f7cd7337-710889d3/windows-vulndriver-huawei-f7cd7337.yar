rule Windows_VulnDriver_Huawei_f7cd7337 {
    meta:
        author = "Elastic Security"
        id = "f7cd7337-f27c-4989-b30b-95fae976bba8"
        fingerprint = "7aaf91e1c10dd4061de44a41e5f45b729b486c001b11948ddde300a8424b9066"
        creation_date = "2026-05-22"
        last_modified = "2026-07-13"
        description = "Subject: Huawei Technologies Co.,Ltd."
        threat_name = "Windows.VulnDriver.Huawei"
        reference_sample = "19a212e6fc324f4cb9ee5eba60f5c1fc0191799a4432265cbeaa3307c76a7fc0"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $subject_name = { 06 03 55 04 03 [2] 48 75 61 77 65 69 20 54 65 63 68 6E 6F 6C 6F 67 69 65 73 20 43 6F 2E 2C 4C 74 64 2E }
        $str1 = "Phymemx64.pdb"
    condition:
        int16(uint32(0x3C) + 0x5c) == 0x0001 and int16(uint32(0x3C) + 0x18) == 0x020b and $subject_name and $str1
}