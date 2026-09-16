rule Windows_VulnDriver_Yundian_dc01ab62 {
    meta:
        author = "Elastic Security"
        id = "dc01ab62-6ab2-4d2c-92d2-cae4766f8f20"
        fingerprint = "97098d0237cfc42491f6bbb41dcbbd93d75374fd60659bc6909b4e5063b3514d"
        creation_date = "2026-05-22"
        last_modified = "2026-07-29"
        description = "Subject: Shenzhen yundian Technology Co., Ltd"
        threat_name = "Windows.VulnDriver.Yundian"
        reference_sample = "668c5bead3c7fcd919afd742ede7e5fe07972dc4cf730ff37deabdd22d88de4a"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $subject_name = { 06 03 55 04 03 [2] 53 68 65 6E 7A 68 65 6E 20 79 75 6E 64 69 61 6E 20 54 65 63 68 6E 6F 6C 6F 67 79 20 43 6F 2E 2C 20 4C 74 64 }
        $str1 = "MyDriver1.pdb"
    condition:
        int16(uint32(0x3C) + 0x5c) == 0x0001 and int16(uint32(0x3C) + 0x18) == 0x020b and $subject_name and $str1
}