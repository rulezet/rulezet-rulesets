rule Windows_VulnDriver_Phoenix_54a54fb1 {
    meta:
        author = "Elastic Security"
        id = "54a54fb1-9f1d-4a48-9984-fbf2e1966a3e"
        fingerprint = "b7be2a221fe995d36bd28c68a2570596b377e7f442be44d22ead7b306ec074c1"
        creation_date = "2026-05-22"
        last_modified = "2026-07-20"
        description = "Subject: Phoenix Technologies Ltd."
        threat_name = "Windows.VulnDriver.Phoenix"
        reference_sample = "2695390a8a7448390fe383beb1eee06d582202683f0273d6e72ef39a8cf709e1"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $subject_name = { 06 03 55 04 03 [2] 50 68 6F 65 6E 69 78 20 54 65 63 68 6E 6F 6C 6F 67 69 65 73 20 4C 74 64 2E }
        $str1 = "TdkLib64.pdb"
        $str2 = "\\Device\\TdkLib"
        $str3 = "\\DosDevices\\TdkLib"
    condition:
        int16(uint32(0x3C) + 0x5c) == 0x0001 and int16(uint32(0x3C) + 0x18) == 0x020b and $subject_name and $str1 and $str2 and $str3
}