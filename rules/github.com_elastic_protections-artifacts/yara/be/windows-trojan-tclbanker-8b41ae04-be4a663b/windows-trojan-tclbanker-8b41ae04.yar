rule Windows_Trojan_TCLBanker_8b41ae04 {
    meta:
        author = "Elastic Security"
        id = "8b41ae04-ef4d-4391-8c4e-0eaa95d7982d"
        fingerprint = "4dd69bcfbf7fd31d10bb5698f225ec0229168f15c76d609df30a9c35fdbd3f80"
        creation_date = "2026-04-28"
        last_modified = "2026-05-05"
        threat_name = "Windows.Trojan.TCLBanker"
        reference_sample = "668f932433a24bbae89d60b24eee4a24808fc741f62c5a3043bb7c9152342f40"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $s1 = "outlook: extraindo contatos" wide fullword
        $s2 = "error: 0 accounts with contacts in Outlook" wide fullword
        $s3 = "GetNamespace('MAPI')" wide fullword
        $s4 = "error: campaign not configured" wide fullword
        $s5 = "-eq 'caixa de entrada'" wide fullword
    condition:
        4 of them
}