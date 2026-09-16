rule Windows_VulnDriver_Intel_89f8af9a {
    meta:
        author = "Elastic Security"
        id = "89f8af9a-0a1a-43ec-85f8-56b6285c1232"
        fingerprint = "0a997d878e8386ead19140d2062ddbadd11f2ed4232aaf4c9e482734fdcc087e"
        creation_date = "2026-05-22"
        last_modified = "2026-07-20"
        description = "Subject: Intel Corporation"
        threat_name = "Windows.VulnDriver.Intel"
        reference_sample = "321104460942bf98c5c248f660e068e5170c16ae8eedfa7acc5bf98471042a4e"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $subject_name = { 06 03 55 04 03 [2] 49 6E 74 65 6C 20 43 6F 72 70 6F 72 61 74 69 6F 6E }
        $str1 = "sepdrv3_15.pdb"
    condition:
        int16(uint32(0x3C) + 0x5c) == 0x0001 and int16(uint32(0x3C) + 0x18) == 0x020b and $subject_name and $str1
}