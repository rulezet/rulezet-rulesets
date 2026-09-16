rule Windows_VulnDriver_KExplore_929d04c4 {
    meta:
        author = "Elastic Security"
        id = "929d04c4-1ad9-4929-9b65-7528fe067883"
        fingerprint = "57ecb673ca1a789d6b6708a23c25a365a99a93f04cfdd1035c6f357ecf4980bf"
        creation_date = "2026-05-22"
        last_modified = "2026-06-24"
        description = "Subject: Pavel Yosifovich"
        threat_name = "Windows.VulnDriver.KExplore"
        reference_sample = "88a9b030ab81082629253c581fe0670019c766f32acfc78a6cdc1080ad272fe4"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $subject_name = { 06 03 55 04 03 [2] 50 61 76 65 6C 20 59 6F 73 69 66 6F 76 69 63 68 }
        $str1 = "KObjExp.pdb"
    condition:
        int16(uint32(0x3C) + 0x5c) == 0x0001 and int16(uint32(0x3C) + 0x18) == 0x020b and $subject_name and $str1
}