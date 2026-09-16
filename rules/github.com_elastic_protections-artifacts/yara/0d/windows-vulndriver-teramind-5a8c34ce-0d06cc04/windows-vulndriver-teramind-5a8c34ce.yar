rule Windows_VulnDriver_Teramind_5a8c34ce {
    meta:
        author = "Elastic Security"
        id = "5a8c34ce-037a-4d10-be73-887f26b63de1"
        fingerprint = "131c4eba08ecf3a483182df6a39affcb81f8d96db35c68afc3f51ccb21195c94"
        creation_date = "2026-05-22"
        last_modified = "2026-07-29"
        description = "Subject: Teramind Inc."
        threat_name = "Windows.VulnDriver.Teramind"
        reference_sample = "2cea1a8d5d23a5ed2c2ac2a0c7c0d95da516aa355224cc707f86de8ade5880ef"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $subject_name = { 06 03 55 04 03 [2] 54 65 72 61 6D 69 6E 64 20 49 6E 63 2E }
        $str1 = "tmfsdrv2.pdb"
        $str2 = "IOCTL_STORAGE_QUERY_PROPERTY"
    condition:
        int16(uint32(0x3C) + 0x5c) == 0x0001 and int16(uint32(0x3C) + 0x18) == 0x020b and $subject_name and $str1 and $str2
}