rule Windows_Rootkit_Generic_5b621593 {
    meta:
        author = "Elastic Security"
        id = "5b621593-ca91-4e58-b8ae-e9a52af633b0"
        fingerprint = "7554cca0506548c001b7e437b6de2125062ac6d0eb9660704b7006a454f57b88"
        creation_date = "2026-07-23"
        last_modified = "2026-08-11"
        description = "Subject: Microsoft Windows Hardware Compatibility Publisher"
        threat_name = "Windows.Rootkit.Generic"
        reference_sample = "274340f7185a0cc047d82ecfb2cce5bd18764ee558b5227894565c2f9fe9f6ab"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $subject_name = { 06 03 55 04 03 [2] 4D 69 63 72 6F 73 6F 66 74 20 57 69 6E 64 6F 77 73 20 48 61 72 64 77 61 72 65 20 43 6F 6D 70 61 74 69 62 69 6C 69 74 79 20 50 75 62 6C 69 73 68 65 72 }
        $seq1 = { 41 BC 01 00 00 00 40 D2 F7 BA 01 00 00 00 40 32 FF F9 0F AC ED A1 BF 01 00 00 00 48 0F AC F5 30 41 D2 C6 45 3A D9 45 32 DB 66 41 0F C1 EE 66 3B FA 41 0F A4 DA 8F D3 E2 8B 48 04 41 81 CE 9A 07 D8 47 }
        $seq2 = { 0F C8 F8 66 F7 C5 D4 0A 40 84 DF 55 40 D2 CD 40 0F 9B C5 31 04 24 66 44 0F A3 F5 41 2A E8 5D 41 F6 C1 BD 48 63 C0 4C 03 D0 41 FF E2 }
    condition:
        int16(uint32(0x3C) + 0x5c) == 0x0001 and int16(uint32(0x3C) + 0x18) == 0x020b and $subject_name and $seq1 and $seq2
}