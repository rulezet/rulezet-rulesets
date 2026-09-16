rule Windows_Trojan_Vidar_4ed00a37 {
    meta:
        author = "Elastic Security"
        id = "4ed00a37-9101-4c54-ad42-06e81051be69"
        fingerprint = "92f3a503d66bc9873691a36f8259aee86948e0b9594e6b8c492b970d9d587500"
        creation_date = "2025-12-16"
        last_modified = "2026-02-02"
        threat_name = "Windows.Trojan.Vidar"
        reference_sample = "0f8976f8b0f6f717ffdfb22cfc1620eee53ce462975bb270929bff3497d22beb"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $a = { 8A 1C 32 44 30 C3 88 1C 31 }
        $b = { 42 8A 1C 1A 44 30 C3 42 88 1C 19 }
    condition:
        all of them
}