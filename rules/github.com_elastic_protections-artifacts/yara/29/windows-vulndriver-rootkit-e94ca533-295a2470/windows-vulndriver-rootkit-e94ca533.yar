rule Windows_VulnDriver_Rootkit_e94ca533 {
    meta:
        author = "Elastic Security"
        id = "e94ca533-1e27-44a6-b8ff-092d47a168db"
        fingerprint = "df111196f95a01031f22cbefa3bde2d6d89f5c99ec31e53d8513e875415a6be3"
        creation_date = "2026-05-22"
        last_modified = "2026-07-29"
        description = "Subject: 湖南蓝途方鼎科技有限公司"
        threat_name = "Windows.VulnDriver.Rootkit"
        reference_sample = "7a84703552ae032a0d1699a081e422ed6c958bbe56d5b41839c8bfa6395bee1d"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $subject_name = { 06 03 55 04 03 [2] E6 B9 96 E5 8D 97 E8 93 9D E9 80 94 E6 96 B9 E9 BC 8E E7 A7 91 E6 8A 80 E6 9C 89 E9 99 90 E5 85 AC E5 8F B8 }
        $str1 = "RedDriver.pdb"
    condition:
        int16(uint32(0x3C) + 0x5c) == 0x0001 and int16(uint32(0x3C) + 0x18) == 0x020b and $subject_name and $str1
}