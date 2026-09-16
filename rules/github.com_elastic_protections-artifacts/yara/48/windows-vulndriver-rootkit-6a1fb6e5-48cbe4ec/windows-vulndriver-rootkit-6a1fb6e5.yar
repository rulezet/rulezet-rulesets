rule Windows_VulnDriver_Rootkit_6a1fb6e5 {
    meta:
        author = "Elastic Security"
        id = "6a1fb6e5-dcfa-4b83-9e43-aeb2f82076cd"
        fingerprint = "d01e5958846990428a8f8dfd15fcc6a53c978be74b3dc208d121b948fe5dd4b9"
        creation_date = "2026-05-22"
        last_modified = "2026-07-29"
        description = "Subject: 重庆貔赑貅软件科技工作室 (王真)"
        threat_name = "Windows.VulnDriver.Rootkit"
        reference_sample = "f154167b4b92851f478b3c3f88423cd719e3139bac5da07f33dd7929796c96f5"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $subject_name = { 06 03 55 04 03 [2] E9 87 8D E5 BA 86 E8 B2 94 E8 B5 91 E8 B2 85 E8 BD AF E4 BB B6 E7 A7 91 E6 8A 80 E5 B7 A5 E4 BD 9C E5 AE A4 20 28 E7 8E 8B E7 9C 9F 29 }
        $str1 = "project-ioctl.pdb"
    condition:
        int16(uint32(0x3C) + 0x5c) == 0x0001 and int16(uint32(0x3C) + 0x18) == 0x020b and $subject_name and $str1
}