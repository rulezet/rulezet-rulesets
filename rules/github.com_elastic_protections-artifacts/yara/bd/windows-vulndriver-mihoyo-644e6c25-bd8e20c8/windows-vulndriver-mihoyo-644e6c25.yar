rule Windows_VulnDriver_Mihoyo_644e6c25 {
    meta:
        author = "Elastic Security"
        id = "644e6c25-17ea-4273-ae4a-23d1a422f8b5"
        fingerprint = "5034d2560b3c3fc802739711f92e83add08959cdfac4688161d0c96f502113e6"
        creation_date = "2026-07-23"
        last_modified = "2026-08-11"
        description = "Subject: miHoYo Co.,Ltd."
        threat_name = "Windows.VulnDriver.Mihoyo"
        reference_sample = "edeb35e4341034b2de389017c4884b081a821f34349a620897a2a845c84cb09e"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $subject_name = { 06 03 55 04 03 [2] 6D 69 48 6F 59 6F 20 43 6F 2E 2C 4C 74 64 2E }
        $seq1 = { 51 41 80 D9 F8 4C 0F A4 D7 DD 48 8B BC 24 90 00 00 00 49 0F A3 EB 66 41 C1 E2 86 81 EF 44 66 67 0C C1 E0 6F F7 D7 24 95 41 D2 EA 81 C7 E2 58 CC 00 40 D2 F5 F8 81 F7 96 3C B3 4A 48 03 F9 48 0F BF E9 66 44 0F BE D1 D2 D4 48 B8 00 00 00 00 01 00 00 00 }
        $seq2 = { D1 CE F5 0F CE 44 84 CD 57 48 C1 F7 76 31 34 24 40 80 D7 BF 66 FF CF 40 FE C7 5F E9 48 14 02 00 }
        $seq3 = { 66 0F B6 33 80 D9 72 C0 E1 AF 8A 4B 02 41 80 D3 A6 66 44 0F BC DD 66 41 0F A3 E3 48 81 EB 06 00 00 00 40 D2 E6 44 0F 4C DC 4D 0F B7 D8 }
    condition:
        int16(uint32(0x3C) + 0x5c) == 0x0001 and int16(uint32(0x3C) + 0x18) == 0x020b and $subject_name and $seq1 and $seq2 and $seq3
}