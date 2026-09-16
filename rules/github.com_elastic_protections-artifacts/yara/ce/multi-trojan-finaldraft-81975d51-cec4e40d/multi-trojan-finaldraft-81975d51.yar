rule Multi_Trojan_FinalDraft_81975d51 {
    meta:
        author = "Elastic Security"
        id = "81975d51-96e9-4a49-97ee-56e2c60e9702"
        fingerprint = "a2d5e2f472499ad6c5ff052eded73fa182bb20cecb9c3921f37bd779a2a77c9b"
        creation_date = "2024-12-03"
        last_modified = "2025-02-04"
        threat_name = "Multi.Trojan.FinalDraft"
        reference_sample = "fa2a6dbc83fe55df848dfcaaf3163f8aaefe0c9727b3ead1da6b9fa78b598f2b"
        severity = 100
        arch_context = "x86, arm64"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "multi"
    strings:
        $a1 = "[-] socket() failed!"
        $a2 = "MailFolders/drafts/messages?$filter=Subject"
        $a3 = "{\"subject\":\"p_%llu\",\"body\":"
        $a4 = "COutLookTransChannel"
        $a5 = "CTransChannel"
        $a6 = "Chrome/40.0.2214.85 Safari/537.36"
    condition:
        3 of them
}