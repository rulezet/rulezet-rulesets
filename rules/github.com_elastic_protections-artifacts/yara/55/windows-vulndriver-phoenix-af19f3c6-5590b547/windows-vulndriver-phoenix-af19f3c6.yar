rule Windows_VulnDriver_Phoenix_af19f3c6 {
    meta:
        author = "Elastic Security"
        id = "af19f3c6-5b97-46a2-a418-3467eb2eab3b"
        fingerprint = "ab65c6680402ca87f4765e8beae8fd05148c8ff2384bdc3d596eae531bd8d2d1"
        creation_date = "2026-05-22"
        last_modified = "2026-07-20"
        description = "Subject: Phoenix Technologies Inc"
        threat_name = "Windows.VulnDriver.Phoenix"
        reference_sample = "03920ed3f904838b65c2065a338f08ce062c40247539345ea8f4c158efe66634"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $subject_name = { 06 03 55 04 03 [2] 50 68 6F 65 6E 69 78 20 54 65 63 68 6E 6F 6C 6F 67 69 65 73 20 49 6E 63 }
        $str1 = "TdkLib64Vs2015.pdb"
        $str2 = "\\Device\\TdkLib"
        $str3 = "\\DosDevices\\TdkLib"
    condition:
        int16(uint32(0x3C) + 0x5c) == 0x0001 and int16(uint32(0x3C) + 0x18) == 0x020b and $subject_name and $str1 and $str2 and $str3
}