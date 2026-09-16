rule Windows_Rootkit_Generic_7f6750a0 {
    meta:
        author = "Elastic Security"
        id = "7f6750a0-4bc9-4707-9c8b-6b25b452a34a"
        fingerprint = "b6c2c84f7479ab17fc6766456a370fc5a50dcfc5970d4e902e445ec3c8779be8"
        creation_date = "2026-07-23"
        last_modified = "2026-08-11"
        description = ""
        threat_name = "Windows.Rootkit.Generic"
        reference_sample = "6165491e8391eac9c0e3b9a2a31e1692a567c16cbfa36d7a88c401ffae1f6c63"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $seq1 = { 48 57 48 83 EC 40 4C 8B C1 48 8D 0C 24 48 2B CA 0F B7 02 66 89 04 11 48 83 C2 02 66 85 C0 75 F0 33 FF 48 8D 14 24 66 41 B9 55 55 66 39 3C 24 74 72 0F B7 0A 66 41 C1 E1 02 44 8B D1 66 44 03 CF 41 C1 EA 06 41 8D 42 FF 83 F8 02 77 56 41 32 C9 66 33 C0 40 2A CF 41 2A CA 66 83 E1 3F 66 83 F9 0A 73 05 8D 41 30 EB 09 }
        $seq2 = { 41 0F B7 04 00 66 43 89 04 18 49 83 C0 02 66 85 C0 75 E6 }
        $seq3 = { 41 BB 44 20 01 AA 8B C1 8B F1 41 3B D3 41 BA 44 30 01 AA 74 0F 41 3B D2 75 11 B8 08 00 00 00 8D 70 FC EB 07 }
    condition:
        int16(uint32(0x3C) + 0x5c) == 0x0001 and int16(uint32(0x3C) + 0x18) == 0x020b and $seq1 and $seq2 and $seq3
}