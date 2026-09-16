rule Windows_Trojan_RevStealer_efc8ff20 {
    meta:
        author = "Elastic Security"
        id = "efc8ff20-a7b8-4a16-95c1-ca8f0c5fc8e9"
        fingerprint = "5b402c9497e33d0f6fa40daa889d07fe2c51752a4c6e70d0b904ce54490c1063"
        creation_date = "2026-08-21"
        last_modified = "2026-09-01"
        threat_name = "Windows.Trojan.RevStealer"
        reference_sample = "127f135246aa0246a8b4d0415538aacdf27f509ff75756556ce18999326f1048"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $seq_str_decrypt = { 48 FF C0 48 89 44 24 ?? ?? ?? FF FF FF 33 C0 48 8B 4C 24 30 48 8B 54 24 38 66 89 44 51 FE 48 83 C4 28 C3 }
        $seq_cred_mgr = { 44 8A 1C 11 41 8D 43 E0 3C 5E 77 }
        $seq_cred_mgr_2 = { 46 8A 1C 01 41 8D 43 E0 3C 5E 77 }
        $seq_parse_module_name = { 48 8B C2 48 2B C1 48 3D FF 00 00 00 7D ?? 0F B6 02 4? ?? ?? ?? ?? ?? 66 41 89 00 }
        $seq_parse_c2 = { 80 FA 39 77 ?? 41 8B 04 24 ?? ?? ?? 8D 0C 80 0F B6 C2 8D 04 48 83 C0 ?? 41 89 04 24 8A 17 80 FA }
        $seq_veh = { 41 B8 A0 00 00 00 4D 8D 0C 12 48 2B CA 4D 2B C2 42 8A 04 09 41 88 01 49 FF C1 49 83 E8 01 }
    condition:
        3 of ($seq*)
}