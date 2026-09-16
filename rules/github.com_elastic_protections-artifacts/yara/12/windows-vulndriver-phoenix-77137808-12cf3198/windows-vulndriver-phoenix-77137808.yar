rule Windows_VulnDriver_Phoenix_77137808 {
    meta:
        author = "Elastic Security"
        id = "77137808-83f7-442b-80b3-58f73c3ef617"
        fingerprint = "6e183cb57b504e0643bf87437d421ca673be127ce533da61ee3084a517929dfb"
        creation_date = "2026-05-22"
        last_modified = "2026-07-20"
        description = "Subject: Phoenix Technologies Ltd."
        threat_name = "Windows.VulnDriver.Phoenix"
        reference_sample = "20d0759b3309603ea085ed31a636e42301df7ddcd358584e2ccd6cabf72af7c3"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $subject_name = { 06 03 55 04 03 [2] 50 68 6F 65 6E 69 78 20 54 65 63 68 6E 6F 6C 6F 67 69 65 73 20 4C 74 64 2E }
        $str1 = "TdkLibVs2015.pdb"
        $str2 = "\\Device\\TdkLib"
        $str3 = "\\DosDevices\\TdkLib"
    condition:
        int16(uint32(0x3C) + 0x5c) == 0x0001 and int16(uint32(0x3C) + 0x18) == 0x020b and $subject_name and $str1 and $str2 and $str3
}