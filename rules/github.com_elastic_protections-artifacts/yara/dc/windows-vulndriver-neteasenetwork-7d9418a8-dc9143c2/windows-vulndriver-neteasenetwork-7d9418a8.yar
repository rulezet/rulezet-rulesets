rule Windows_VulnDriver_NetEaseNetwork_7d9418a8 {
    meta:
        author = "Elastic Security"
        id = "7d9418a8-5f7f-4439-8102-80ea7e211d89"
        fingerprint = "839e56a3847eb36f11ea39edd07d25fcb1a3991bd534fb5ab4c860f1dfd59085"
        creation_date = "2026-05-22"
        last_modified = "2026-07-20"
        description = "Subject: NetEase(Hangzhou) Network Co. Ltd."
        threat_name = "Windows.VulnDriver.NetEaseNetwork"
        reference_sample = "4448beff8366e42e3393e8c7f8261aee0b0340356c31aa3b97de07452ae01888"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $subject_name = { 06 03 55 04 03 [2] 4E 65 74 45 61 73 65 28 48 61 6E 67 7A 68 6F 75 29 20 4E 65 74 77 6F 72 6B 20 43 6F 2E 20 4C 74 64 2E }
        $str1 = "WinRing0.pdb"
    condition:
        int16(uint32(0x3C) + 0x5c) == 0x0001 and $subject_name and $str1
}