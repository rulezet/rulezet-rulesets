rule Windows_VulnDriver_AMD_e4d6777c {
    meta:
        author = "Elastic Security"
        id = "e4d6777c-1861-42ec-a01d-088a6279acf9"
        fingerprint = "8a0e1046a815c99a8e7fb513e3d1b5ae8d99de34319d4e7ba591a3d255aafee0"
        creation_date = "2026-04-02"
        last_modified = "2026-06-25"
        description = "Subject: Advanced Micro Devices, Inc."
        threat_name = "Windows.VulnDriver.AMD"
        reference_sample = "478bcb750017cb6541f3dd0d08a47370f3c92eec998bc3825b5d8e08ee831b70"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $subject_name = { 06 03 55 04 03 [2] 41 64 76 61 6E 63 65 64 20 4D 69 63 72 6F 20 44 65 76 69 63 65 73 2C 20 49 6E 63 2E }
        $str1 = "AODDriver.pdb"
    condition:
        int16(uint32(0x3C) + 0x5c) == 0x0001 and int16(uint32(0x3C) + 0x18) == 0x020b and $subject_name and $str1
}