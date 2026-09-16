rule Windows_Trojan_Metasploit_1ca1e384 {
    meta:
        author = "Elastic Security"
        id = "1ca1e384-267b-49d8-ab4c-fb311892a07c"
        fingerprint = "a04268061fc4680058a374ede37f91aa8b85a06da67a4c4d81dae256c72e25db"
        creation_date = "2025-05-02"
        last_modified = "2025-05-27"
        threat_name = "Windows.Trojan.Metasploit"
        severity = 100
        arch_context = "x86, arm64"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $a = { 48 01 D0 66 81 78 18 0B 02 0F 85 72 00 00 00 8B 80 88 00 00 00 48 85 C0 74 67 48 01 D0 }
    condition:
        all of them
}