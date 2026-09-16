rule Windows_VulnDriver_Elitegroup_4ae43f88 {
    meta:
        author = "Elastic Security"
        id = "4ae43f88-a44c-4434-9b14-210fd3d5d082"
        fingerprint = "7f21a57f215caf22401a4663874b567d10ce8c9c64d20390739924319faa5be4"
        creation_date = "2026-05-22"
        last_modified = "2026-07-13"
        description = "Subject: Elitegroup Computer Systems Co., Ltd."
        threat_name = "Windows.VulnDriver.Elitegroup"
        reference_sample = "14edfdc13aeb98db50d597367f132443b086df0728f4fdb8c3bb5d47a8a0cd4a"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $subject_name = { 06 03 55 04 03 [2] 45 6C 69 74 65 67 72 6F 75 70 20 43 6F 6D 70 75 74 65 72 20 53 79 73 74 65 6D 73 20 43 6F 2E 2C 20 4C 74 64 2E }
        $str1 = "ECSIoDriver.pdb"
    condition:
        int16(uint32(0x3C) + 0x5c) == 0x0001 and $subject_name and $str1
}