rule Windows_VulnDriver_Phoenix_c655e0a4 {
    meta:
        author = "Elastic Security"
        id = "c655e0a4-f952-4074-8b70-8c7b9c0b473a"
        fingerprint = "1817d49c5625bc0d2d11327c2caa32f11cc75ec6ef750c8759d63c2ca378e05b"
        creation_date = "2026-05-22"
        last_modified = "2026-07-20"
        description = "Subject: Phoenix Technologies Inc"
        threat_name = "Windows.VulnDriver.Phoenix"
        reference_sample = "7b2ed5b6f6296cdd3e61a915707355bd5325ce7f5a6fab43b7e1e550277ecaed"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $subject_name = { 06 03 55 04 03 [2] 50 68 6F 65 6E 69 78 20 54 65 63 68 6E 6F 6C 6F 67 69 65 73 20 49 6E 63 }
        $str1 = "TdkLib64.pdb"
        $str2 = "\\Device\\TdkLib"
        $str3 = "\\DosDevices\\TdkLib"
    condition:
        int16(uint32(0x3C) + 0x5c) == 0x0001 and int16(uint32(0x3C) + 0x18) == 0x020b and $subject_name and $str1 and $str2 and $str3
}