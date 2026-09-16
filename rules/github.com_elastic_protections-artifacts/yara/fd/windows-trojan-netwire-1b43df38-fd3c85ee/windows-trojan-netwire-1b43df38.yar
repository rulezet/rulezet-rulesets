rule Windows_Trojan_Netwire_1b43df38 {
    meta:
        author = "Elastic Security"
        id = "1b43df38-886e-4f58-954a-a09f30f19907"
        fingerprint = "4142ea14157939dc23b8d1f5d83182aef3a5877d2506722f7a2706b7cb475b76"
        creation_date = "2021-06-28"
        last_modified = "2021-08-23"
        threat_name = "Windows.Trojan.Netwire"
        reference = "https://www.elastic.co/security-labs/netwire-dynamic-configuration-extraction"
        reference_sample = "e6f446dbefd4469b6c4d24988dd6c9ccd331c8b36bdbc4aaf2e5fc49de2c3254"
        severity = 100
        arch_context = "x86, arm64"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $a1 = "[%.2d/%.2d/%d %.2d:%.2d:%.2d]" fullword
        $a2 = "\\Login Data"
        $a3 = "SOFTWARE\\NetWire" fullword
    condition:
        2 of them
}