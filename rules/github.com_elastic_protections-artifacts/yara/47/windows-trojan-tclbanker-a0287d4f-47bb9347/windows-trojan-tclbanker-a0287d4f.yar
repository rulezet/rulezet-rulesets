rule Windows_Trojan_TCLBanker_a0287d4f {
    meta:
        author = "Elastic Security"
        id = "a0287d4f-b3c8-4299-a13e-592ba5192491"
        fingerprint = "6e07ed3db08c2e1da8003efab2730e97f7a9242717363f48fe1b1368821e45dd"
        creation_date = "2026-04-27"
        last_modified = "2026-05-05"
        threat_name = "Windows.Trojan.TCLBanker"
        reference_sample = "8a174aa70a4396547045aef6c69eb0259bae1706880f4375af71085eeb537059"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $str_decrypt = { 48 8D 41 1C 45 33 C0 48 8B C8 41 B9 FF 00 00 00 41 8D 50 23 }
        $str_decrypt2 = { 66 33 51 EC 66 89 11 48 8D 49 02 49 83 F8 0A }
        $syscall = { 75 1B 41 80 7F 01 8B 75 14 41 80 7F 02 D1 75 0D 41 80 7F 03 B8 75 06 }
        $etw_patch = { BA 03 00 00 00 66 C7 03 33 C0 48 8B CB C6 43 02 C3 }
        $gate = { 48 B8 F5 08 1D 97 3C E2 54 AB 48 89 44 24 48 48 B8 FD FE D9 45 25 B9 2E 95 }
        $lang_check = { BA FF 03 00 00 8B C8 66 23 C2 66 83 F8 16 75 }
        $watchdog = "WATCHDOG: thread count suspicious (baseline=%d, current=%d, delta=%d)" ascii fullword
    condition:
        3 of them
}