rule Windows_VulnDriver_Asus_a4b6c6c9 {
    meta:
        author = "Elastic Security"
        id = "a4b6c6c9-7e5f-4e19-b4e4-c263fe851f0c"
        fingerprint = "502bc2770b386ab8122ce38f1d17c26d3e7e4b0a8f0f2e9ed4a7818b4d34b88a"
        creation_date = "2026-05-22"
        last_modified = "2026-06-25"
        description = "Subject: ASUSTeK Computer Inc."
        threat_name = "Windows.VulnDriver.Asus"
        reference_sample = "8f23313adb35782adb0ba97fefbfbb8bbc5fc40ae272e07f6d4629a5305a3fa2"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $subject_name = { 06 03 55 04 03 [2] 41 53 55 53 54 65 4B 20 43 6F 6D 70 75 74 65 72 20 49 6E 63 2E }
        $str1 = "AsUpIO64.pdb"
    condition:
        int16(uint32(0x3C) + 0x5c) == 0x0001 and int16(uint32(0x3C) + 0x18) == 0x020b and $subject_name and $str1
}