rule Windows_VulnDriver_Rootkit_aa10c0ad {
    meta:
        author = "Elastic Security"
        id = "aa10c0ad-de61-4a47-bdbe-f232e4e383e2"
        fingerprint = "e8da953d36cd407c1e56e89f50609f2a66c507d5900a1205ce6f25c7be1345ce"
        creation_date = "2026-05-22"
        last_modified = "2026-07-29"
        description = "Subject: Zhuhai liancheng Technology Co., Ltd."
        threat_name = "Windows.VulnDriver.Rootkit"
        reference_sample = "0440ef40c46fdd2b5d86e7feef8577a8591de862cfd7928cdbcc8f47b8fa3ffc"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $subject_name = { 06 03 55 04 03 [2] 5A 68 75 68 61 69 20 6C 69 61 6E 63 68 65 6E 67 20 54 65 63 68 6E 6F 6C 6F 67 79 20 43 6F 2E 2C 20 4C 74 64 2E }
        $str1 = "KApcHelper.pdb"
    condition:
        int16(uint32(0x3C) + 0x5c) == 0x0001 and int16(uint32(0x3C) + 0x18) == 0x020b and $subject_name and $str1
}