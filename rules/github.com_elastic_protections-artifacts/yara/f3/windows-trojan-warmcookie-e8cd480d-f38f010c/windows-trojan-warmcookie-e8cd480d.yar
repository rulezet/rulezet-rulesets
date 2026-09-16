rule Windows_Trojan_WarmCookie_e8cd480d {
    meta:
        author = "Elastic Security"
        id = "e8cd480d-a85e-4d5f-878c-287d02bfa67c"
        fingerprint = "28954a5df5d4c331403ac393843b12bc434b28cff359305e9a1d88232277491d"
        creation_date = "2024-09-20"
        last_modified = "2024-09-30"
        threat_name = "Windows.Trojan.WarmCookie"
        reference = "https://www.elastic.co/security-labs/dipping-into-danger"
        reference_sample = "f4d2c9470b322af29b9188a3a590cbe85bacb9cc8fcd7c2e94d82271ded3f659"
        severity = 100
        arch_context = "x86, arm64"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $seq1 = { 83 F8 0F 7D 14 E8 [4] 83 F8 05 7D 0A E8 }
        $seq2 = { 72 ?? E8 [4] 3D 00 0F 00 00 7? }
        $seq3 = { B9 E8 03 00 00 FF 15 }
        $seq4 = { 41 B9 04 00 00 00 4C 8D ?4 24 }
        $seq5 = { 48 C7 C1 02 00 00 80 FF 15 [4] 85 C0 0F 85 }
    condition:
        4 of them
}