rule Windows_VulnDriver_Nvidia_a23a3872 {
    meta:
        author = "Elastic Security"
        id = "a23a3872-24ac-4164-b867-3f74d476f85d"
        fingerprint = "126a12b57ac2afd8e9d60624ec7b56550bd29f91df94c5461b0b470c018610d8"
        creation_date = "2026-05-22"
        last_modified = "2026-07-20"
        description = "Subject: NVIDIA Corporation"
        threat_name = "Windows.VulnDriver.Nvidia"
        reference_sample = "506f953bbb285aeb8af0549eb24f52f3b7af36afe740afa36735bac70573ce28"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $subject_name = { 06 03 55 04 03 [2] 4E 56 49 44 49 41 20 43 6F 72 70 6F 72 61 74 69 6F 6E }
        $str1 = "AsIO.pdb"
    condition:
        int16(uint32(0x3C) + 0x5c) == 0x0001 and int16(uint32(0x3C) + 0x18) == 0x020b and $subject_name and $str1
}