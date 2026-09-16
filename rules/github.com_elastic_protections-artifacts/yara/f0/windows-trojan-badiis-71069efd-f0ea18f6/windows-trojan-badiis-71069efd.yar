rule Windows_Trojan_BadIIS_71069efd {
    meta:
        author = "Elastic Security"
        id = "71069efd-75a4-4752-8b31-a8ac0a17cfc0"
        fingerprint = "e775c597c743e41dd11e4aedce991609d81764fd3b31ed29efcea1cc57fce81f"
        creation_date = "2026-01-26"
        last_modified = "2026-02-02"
        threat_name = "Windows.Trojan.BadIIS"
        reference_sample = "c5abe6936fe111bbded1757a90c934a9e18d849edd70e56a451c1547688ff96f"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $a1 = "hm.baidu.com/hm.js" fullword
        $a2 = "googletagmanager.com/gtag/js?id" fullword
        $a3 = "</div>\n<a id=\"js-alert-btn\" class=\"alert-btn\" href=\"" fullword
        $a4 = "index.php?domain=" fullword
        $seq1 = { C7 45 C4 [4] C7 45 C8 04 00 00 00 C7 45 CC [4] C7 45 D0 04 00 00 00 }
        $seq2 = { C7 45 E8 07 00 00 00 C7 45 EC [4] C7 45 F0 04 00 00 00 C7 45 F4 [4] C7 45 F8 09 00 00 00 }
    condition:
        2 of ($a*) and 1 of ($seq*)
}