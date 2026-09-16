rule Windows_VulnDriver_Huawei_fbb14476 {
    meta:
        author = "Elastic Security"
        id = "fbb14476-6e19-41ec-bbde-322860c593a2"
        fingerprint = "674e6cc8247cc020b698ab4fc12449aa505032d3696c059555f6a839bd5a4482"
        creation_date = "2026-05-22"
        last_modified = "2026-07-13"
        description = "Subject: Huawei Technologies Co., Ltd."
        threat_name = "Windows.VulnDriver.Huawei"
        reference_sample = "13a38c92606de7bc61960606deb59e1db125fb4efbb8b29ba732e5d3c2dc169c"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $subject_name = { 06 03 55 04 03 [2] 48 75 61 77 65 69 20 54 65 63 68 6E 6F 6C 6F 67 69 65 73 20 43 6F 2E 2C 20 4C 74 64 2E }
        $str1 = "winio64.pdb"
    condition:
        int16(uint32(0x3C) + 0x5c) == 0x0001 and int16(uint32(0x3C) + 0x18) == 0x020b and $subject_name and $str1
}