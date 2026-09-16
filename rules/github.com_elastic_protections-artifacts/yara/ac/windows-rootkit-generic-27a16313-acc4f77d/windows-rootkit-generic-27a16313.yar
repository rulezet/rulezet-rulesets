rule Windows_Rootkit_Generic_27a16313 {
    meta:
        author = "Elastic Security"
        id = "27a16313-d6d5-4c51-bdff-e693f794ecc2"
        fingerprint = "92783cb21c84ba4aaef32d6fc3735a197771f76d2131907f9a28b0916e5d1cea"
        creation_date = "2026-07-21"
        last_modified = "2026-08-11"
        description = "Subject: Microsoft Windows Hardware Compatibility Publisher"
        threat_name = "Windows.Rootkit.Generic"
        reference_sample = "ee8844ffd3879190fb389b0f613cb2dcdcd83375cf0a6994170a648c5ca8c479"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $seq1 = { 33 C0 48 89 44 24 20 66 89 44 24 28 0F 01 4C 24 20 48 8B 4C 24 22 48 85 C9 0F 84 D4 00 00 00 8B FE 49 BE 00 00 00 00 00 F0 FF FF 0F 1F 84 00 00 00 00 00 }
        $seq2 = { BA C0 AB 8E F3 48 8B CB E8 B7 F6 FF FF }
        $str1 = "\\Device\\devhost" wide
    condition:
        int16(uint32(0x3C) + 0x5c) == 0x0001 and int16(uint32(0x3C) + 0x18) == 0x020b and $seq1 and $seq2 and $str1
}