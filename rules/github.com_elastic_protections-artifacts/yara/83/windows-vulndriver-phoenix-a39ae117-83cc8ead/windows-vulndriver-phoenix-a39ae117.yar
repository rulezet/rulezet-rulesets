rule Windows_VulnDriver_Phoenix_a39ae117 {
    meta:
        author = "Elastic Security"
        id = "a39ae117-3ca3-4e16-adf7-cc86a3381300"
        fingerprint = "8586bf3934a76d1395e1fcf19aa333a50ab43aa0d4e4407601817598ac1a8e38"
        creation_date = "2026-05-22"
        last_modified = "2026-07-20"
        description = "Subject: Phoenix Technologies Ltd."
        threat_name = "Windows.VulnDriver.Phoenix"
        reference_sample = "39f137083e6c0200543e1f8d3c074f857d141bdb8c8f09338d48520537b881aa"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $subject_name = { 06 03 55 04 03 [2] 50 68 6F 65 6E 69 78 20 54 65 63 68 6E 6F 6C 6F 67 69 65 73 20 4C 74 64 2E }
        $str1 = "TdkLib64Vs2015.pdb"
        $str2 = "\\Device\\TdkLib"
        $str3 = "\\DosDevices\\TdkLib"
    condition:
        int16(uint32(0x3C) + 0x5c) == 0x0001 and int16(uint32(0x3C) + 0x18) == 0x020b and $subject_name and $str1 and $str2 and $str3
}