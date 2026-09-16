rule Windows_Rootkit_Generic_6eff9444 {
    meta:
        author = "Elastic Security"
        id = "6eff9444-3faf-4373-9e92-289702b5dd50"
        fingerprint = "70d05bcdc6e1e77af98f8cbd67565aaf298eb2803b7d27a7d4678dd62337ae22"
        creation_date = "2026-07-22"
        last_modified = "2026-08-11"
        description = "Subject: Fuzhou Dingxin Trade Co., Ltd."
        threat_name = "Windows.Rootkit.Generic"
        reference_sample = "927e3aef03a8355d236230cace376b3023480a40c5ac08453c07dab343dd1f11"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $subject_name = { 06 03 55 04 03 [2] 46 75 7A 68 6F 75 20 44 69 6E 67 78 69 6E 20 54 72 61 64 65 20 43 6F 2E 2C 20 4C 74 64 2E }
        $seq1 = { 82 54 FB 7A BF 7D 81 AB 93 BD 7D E2 9A E4 13 43 82 46 1E 2F E8 8A }
        $seq2 = { 3B B3 60 B9 26 82 1A 76 B4 70 3E AF 67 7D B7 5C 4E 11 6E D1 B6 65 7C 2C 8C 8E 57 C9 07 60 }
    condition:
        int16(uint32(0x3C) + 0x5c) == 0x0001 and int16(uint32(0x3C) + 0x18) == 0x020b and $subject_name and $seq1 and $seq2
}