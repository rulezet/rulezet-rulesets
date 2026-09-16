rule Windows_VulnDriver_PartnerTech_fcaf8fe7 {
    meta:
        author = "Elastic Security"
        id = "fcaf8fe7-8e6f-4509-9930-a5d04914cdd4"
        fingerprint = "f977496a0f1b9f97ebd770c7131d9df024675d9cf8fcc26bcc72159c593462ec"
        creation_date = "2026-05-22"
        last_modified = "2026-07-20"
        description = "Subject: Partner Tech(Shanghai)Co.,Ltd"
        threat_name = "Windows.VulnDriver.PartnerTech"
        reference_sample = "752565bab29cd2c63b4ff59a8c637bed02c2689781067ddf7cfc5c5221eb1d68"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $subject_name = { 06 03 55 04 03 [2] 50 61 72 74 6E 65 72 20 54 65 63 68 28 53 68 61 6E 67 68 61 69 29 43 6F 2E 2C 4C 74 64 }
        $str1 = "WinIo64C.pdb"
    condition:
        int16(uint32(0x3C) + 0x5c) == 0x0001 and int16(uint32(0x3C) + 0x18) == 0x020b and $subject_name and $str1
}