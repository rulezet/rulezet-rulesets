rule Windows_Trojan_TCLBanker_b5ef38c0 {
    meta:
        author = "Elastic Security"
        id = "b5ef38c0-fada-44e6-85ae-f7e7747f9996"
        fingerprint = "7af8112c19d301db1fa0a7605088b4b294a7b5ba20008c1f71bda46fc1babffd"
        creation_date = "2026-04-28"
        last_modified = "2026-05-05"
        threat_name = "Windows.Trojan.TCLBanker"
        reference_sample = "701d51b7be8b034c860bf97847bd59a87dca8481c4625328813746964995b626"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $s1 = "no_session: QR code detectado, sem conta logada" wide fullword
        $s2 = "error: campaign not configured" wide fullword
        $s3 = "error: 0 contacts after filter" wide fullword
        $s4 = "whatsapp: sessao carregada" wide fullword
        $s5 = "wpp_inject_failed" wide fullword
    condition:
        4 of them
}