rule Macos_Infostealer_Banshee_cde28dbe {
    meta:
        author = "Elastic Security"
        id = "cde28dbe-10b5-4da4-898c-412d7376e296"
        fingerprint = "ce349c617b19e2fcab1c1d316e16d414a45ed57eb3b3cab91b4c9b177f591875"
        creation_date = "2024-10-29"
        last_modified = "2025-08-18"
        threat_name = "Macos.Infostealer.Banshee"
        reference_sample = "63598afdf56de10043289a7489cccf6c71c203bc68f165f66d2a06e04b65a225"
        severity = 100
        arch_context = "x86, arm64"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "macos"
    strings:
        $str_0 = "dumpKeychainPasswords" ascii fullword
        $str_1 = "compressFolder:" ascii fullword
        $str_2 = "collectWalletData" ascii fullword
        $str_3 = "getMacOSPassword" ascii fullword
        $str_4 = "collectDataFromBrowser:browserPath:" ascii fullword
        $str_5 = "Exodus/exodus.wallet/"
        $b_0 = { 64 69 73 70 6C 61 79 20 64 69 61 6C 6F 67 20 22 54 6F 20 6C 61 75 6E 63 68 20 74 68 65 20 61 70 70 6C 69 63 61 74 69 6F 6E 2C 20 79 6F 75 20 6E 65 65 64 20 74 6F 20 75 70 64 61 74 65 20 74 68 65 20 73 79 73 74 65 6D 20 73 65 74 74 69 6E 67 73 20 0A 0A 50 6C 65 61 73 65 20 65 6E 74 65 72 20 79 6F 75 72 20 70 61 73 73 77 6F 72 64 2E 22 20 77 69 74 68 20 74 69 74 6C 65 20 22 53 79 73 74 65 6D 20 50 72 65 66 65 72 65 6E 63 65 73 22 20 77 69 74 68 20 69 63 6F 6E 20 63 61 75 74 69 6F 6E 20 64 65 66 61 75 6C 74 20 61 6E 73 77 65 72 20 22 22 20 67 69 76 69 6E 67 20 75 70 20 61 66 74 65 72 20 33 30 20 77 69 74 68 20 68 69 64 64 65 6E 20 61 6E 73 77 65 72 27 }
    condition:
        all of ($str_*) or $b_0
}