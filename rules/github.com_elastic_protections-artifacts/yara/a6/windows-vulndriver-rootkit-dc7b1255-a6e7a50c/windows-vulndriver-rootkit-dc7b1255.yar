rule Windows_VulnDriver_Rootkit_dc7b1255 {
    meta:
        author = "Elastic Security"
        id = "dc7b1255-513d-4e8a-9dd1-1903a931d32a"
        fingerprint = "acf2f2b7ed2fbc2be6152cf5476253db65cb821ceeef209d1dcfc01c7a0ecf0e"
        creation_date = "2026-05-22"
        last_modified = "2026-07-29"
        description = "Subject: Beijing Founder Apabi Technology Limited"
        threat_name = "Windows.VulnDriver.Rootkit"
        reference_sample = "df72cb33a23ae8f6f9dc64bb738fcfaea959368ce05cf399f3c7db5e90104bd7"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $subject_name = { 06 03 55 04 03 [2] 42 65 69 6A 69 6E 67 20 46 6F 75 6E 64 65 72 20 41 70 61 62 69 20 54 65 63 68 6E 6F 6C 6F 67 79 20 4C 69 6D 69 74 65 64 }
        $str1 = "MDriver.pdb"
    condition:
        int16(uint32(0x3C) + 0x5c) == 0x0001 and int16(uint32(0x3C) + 0x18) == 0x020b and $subject_name and $str1
}