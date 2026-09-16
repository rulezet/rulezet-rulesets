rule Windows_Trojan_TCLBanker_5df0f971 {
    meta:
        author = "Elastic Security"
        id = "5df0f971-0a77-43aa-a62f-8f10ff1be1e9"
        fingerprint = "2a857ea549a5129ff3cfc23ca2c26ce986b0c154a070638bb3d65946a8ec7542"
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
        $s1 = "[Persistence] EnsureInstalled: exe=" wide fullword
        $s2 = "[Persistence] Task deleted OK" wide fullword
        $s3 = "CommandLine FROM Win32_Process WHERE Name = 'msedge.exe'" wide fullword
        $s4 = "KeyloggerHookThread" wide fullword
        $s5 = "Fique atento ao telefone informado" wide fullword
        $s6 = "O telefone deve ter 10" wide fullword
        $s7 = "Trabalhando em atualizacoes" wide fullword
        $s8 = "Win32_Process.Create falhou com codigo" wide fullword
    condition:
        4 of them
}