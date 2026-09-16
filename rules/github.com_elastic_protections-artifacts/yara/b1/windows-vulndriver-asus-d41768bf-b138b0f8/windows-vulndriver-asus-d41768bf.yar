rule Windows_VulnDriver_Asus_d41768bf {
    meta:
        author = "Elastic Security"
        id = "d41768bf-e91e-4ae7-b98e-9b0061f4ac36"
        fingerprint = "0734b9545b8b8fff3d9f7d4eec29ae873d01406d8a2dbcce4071ede226f0ff03"
        creation_date = "2026-05-22"
        last_modified = "2026-06-25"
        description = "Subject: ASUSTeK Computer Inc."
        threat_name = "Windows.VulnDriver.Asus"
        reference_sample = "61a1bdddd3c512e681818debb5bee94db701768fc25e674fcad46592a3259bd0"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $subject_name = { 06 03 55 04 03 [2] 41 53 55 53 54 65 4B 20 43 6F 6D 70 75 74 65 72 20 49 6E 63 2E }
        $str1 = "GLCKIO2.pdb"
    condition:
        int16(uint32(0x3C) + 0x5c) == 0x0001 and int16(uint32(0x3C) + 0x18) == 0x020b and $subject_name and $str1
}