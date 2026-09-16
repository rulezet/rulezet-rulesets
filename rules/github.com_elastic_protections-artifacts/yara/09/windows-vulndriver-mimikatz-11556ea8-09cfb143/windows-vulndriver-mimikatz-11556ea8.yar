rule Windows_VulnDriver_Mimikatz_11556ea8 {
    meta:
        author = "Elastic Security"
        id = "11556ea8-d2b5-488a-beba-3149a7b9984a"
        fingerprint = "4cff64faabc66be451a206610eea5e20021963896223e275bff21fca0f31abd4"
        creation_date = "2026-05-22"
        last_modified = "2026-07-20"
        description = "Subject: Benjamin Delpy"
        threat_name = "Windows.VulnDriver.Mimikatz"
        reference_sample = "af7ca247bf229950fb48674b21712761ac650d33f13a4dca44f61c59f4c9ac46"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $subject_name = { 06 03 55 04 03 [2] 42 65 6E 6A 61 6D 69 6E 20 44 65 6C 70 79 }
        $str1 = "mimidrv.pdb"
    condition:
        int16(uint32(0x3C) + 0x5c) == 0x0001 and int16(uint32(0x3C) + 0x18) == 0x020b and $subject_name and $str1
}