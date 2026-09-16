rule Windows_Trojan_GhostPulse_bb38fcb3 {
    meta:
        author = "Elastic Security"
        id = "bb38fcb3-c781-4fcd-9f1d-ae20da565365"
        fingerprint = "b2e96e25b7c663a3b8902f4d0413cef3563a57c517219443896e3ed8630eab94"
        creation_date = "2024-10-15"
        last_modified = "2024-10-24"
        threat_name = "Windows.Trojan.GhostPulse"
        reference_sample = "b54d9db283e6c958697bfc4f97a5dd0ba585bc1d05267569264a2d700f0799ae"
        severity = 100
        arch_context = "x86, arm64"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $stage_1 = { 49 63 D0 42 8B 0C 0A 41 03 CA 89 0C 1A 8B 05 ?? ?? ?? ?? 44 03 C0 8B 05 ?? ?? ?? ?? 44 3B C0 }
        $stage_2 = { 48 89 01 48 8B 84 24 D8 00 00 00 48 8B 4C 24 78 8B 49 0C 89 08 C7 44 24 44 00 00 00 00 }
    condition:
        any of them
}