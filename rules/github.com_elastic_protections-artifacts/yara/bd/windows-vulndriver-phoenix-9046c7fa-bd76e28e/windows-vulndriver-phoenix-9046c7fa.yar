rule Windows_VulnDriver_Phoenix_9046c7fa {
    meta:
        author = "Elastic Security"
        id = "9046c7fa-d100-44f1-b229-6b5cdf96a65e"
        fingerprint = "7a46b350a0c754b63d80330772535a905f755add7b1fe6f5af5de5df15bac977"
        creation_date = "2026-05-22"
        last_modified = "2026-07-20"
        description = "Subject: Phoenix Technologies Ltd."
        threat_name = "Windows.VulnDriver.Phoenix"
        reference_sample = "45a74b2e7ab35dc783375a4603efd961f6dfefaf3c134d453d6b76af94607e74"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $subject_name = { 06 03 55 04 03 [2] 50 68 6F 65 6E 69 78 20 54 65 63 68 6E 6F 6C 6F 67 69 65 73 20 4C 74 64 2E }
        $str1 = "TdkLib.pdb"
        $str2 = "\\Device\\TdkLib"
        $str3 = "\\DosDevices\\TdkLib"
    condition:
        int16(uint32(0x3C) + 0x5c) == 0x0001 and $subject_name and $str1 and $str2 and $str3
}