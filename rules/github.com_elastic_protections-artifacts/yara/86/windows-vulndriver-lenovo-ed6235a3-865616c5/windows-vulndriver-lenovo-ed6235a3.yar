rule Windows_VulnDriver_Lenovo_ed6235a3 {
    meta:
        author = "Elastic Security"
        id = "ed6235a3-1ae6-4680-8234-9e902027e77a"
        fingerprint = "09911ecad47fff861c55be7396c487f56f7d7a4ceddd1e4abf4024ec3ec89e10"
        creation_date = "2026-05-22"
        last_modified = "2026-07-20"
        description = "Subject: Lenovo"
        threat_name = "Windows.VulnDriver.Lenovo"
        reference_sample = "ff0892697771f1a9968423793faa34008cfa0041fee48d5b52b25314f7a6a7b4"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $subject_name = { 06 03 55 04 03 [2] 4C 65 6E 6F 76 6F }
        $str1 = "NetworkLocker_x64.pdb"
        $str2 = "IOCTL_WORKLOCK_NTLKD"
        $str3 = "IOCTL_WORKLOCK_NTLKE"
    condition:
        int16(uint32(0x3C) + 0x5c) == 0x0001 and int16(uint32(0x3C) + 0x18) == 0x020b and $subject_name and $str1 and $str2 and $str3
}