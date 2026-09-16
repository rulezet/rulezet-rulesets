rule Windows_Rootkit_Generic_362cd75f {
    meta:
        author = "Elastic Security"
        id = "362cd75f-519a-442e-a9af-5017b33449a8"
        fingerprint = "9dc485bb7f0630fdfe352e0d2a5da23f8ea9e51ad887a9ff616c40c66e85db3b"
        creation_date = "2026-07-23"
        last_modified = "2026-08-11"
        description = "Subject: 长沙恒祥信息技术有限公司"
        threat_name = "Windows.Rootkit.Generic"
        reference_sample = "d51d00127ddd4551fb1eafe14255715014944ad4c60eabb9e568c3ff98ff4a2e"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $subject_name = { 06 03 55 04 03 [2] E9 95 BF E6 B2 99 E6 81 92 E7 A5 A5 E4 BF A1 E6 81 AF E6 8A 80 E6 9C AF E6 9C 89 E9 99 90 E5 85 AC E5 8F B8 }
        $seq1 = { 41 54 48 C7 44 24 08 EB 0A B7 70 48 8D 64 24 08 E8 F9 3A 14 00 E8 33 73 B8 FF C9 EC }
    condition:
        int16(uint32(0x3C) + 0x5c) == 0x0001 and int16(uint32(0x3C) + 0x18) == 0x020b and $subject_name and $seq1
}