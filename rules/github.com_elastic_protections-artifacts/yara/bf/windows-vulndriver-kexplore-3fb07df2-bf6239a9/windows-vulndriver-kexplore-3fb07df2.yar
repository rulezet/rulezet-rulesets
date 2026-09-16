rule Windows_VulnDriver_KExplore_3fb07df2 {
    meta:
        author = "Elastic Security"
        id = "3fb07df2-c7bf-4ded-b9ea-9f16234a4e1b"
        fingerprint = "34d14ddfa4f95a47d61fd418616c71122c98f6df62194551acafa3f530af9aba"
        creation_date = "2026-05-22"
        last_modified = "2026-06-24"
        description = "Subject: Pavel Yosifovich"
        threat_name = "Windows.VulnDriver.KExplore"
        reference_sample = "c71e14961ac29165ddf6e5e8f9372e82fc79494da07afbfaf2ccfc9bd3bbbe18"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $subject_name = { 06 03 55 04 03 [2] 50 61 76 65 6C 20 59 6F 73 69 66 6F 76 69 63 68 }
        $str1 = "KExplore.pdb"
    condition:
        int16(uint32(0x3C) + 0x5c) == 0x0001 and int16(uint32(0x3C) + 0x18) == 0x020b and $subject_name and $str1
}