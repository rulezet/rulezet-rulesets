rule Windows_Trojan_IcedID_81eff9a3 {
    meta:
        author = "Elastic Security"
        id = "81eff9a3-4c75-48a5-8160-718c9a2d1e14"
        fingerprint = "f764c4b2a562eb92a7326a45b180da7f930ffcc4f0b88bbd640c2fe7b71f82b6"
        creation_date = "2023-05-05"
        last_modified = "2023-06-13"
        description = "IcedID fork core bot loader"
        threat_name = "Windows.Trojan.IcedID"
        reference = "https://www.elastic.co/security-labs/thawing-the-permafrost-of-icedid-summary"
        reference_sample = "96dacdf50d1db495c8395d7cf454aa3a824801cf366ac368fe496f89b5f98fe7"
        severity = 100
        arch_context = "x86, arm64"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $a = "E:\\source\\anubis\\int-bot\\x64\\Release\\int-bot.pdb" ascii fullword
    condition:
        all of them
}