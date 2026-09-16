rule Windows_Trojan_Guloader_2f1e44c8 {
    meta:
        author = "Elastic Security"
        id = "2f1e44c8-f269-4cd6-a516-8d9282ddcfbc"
        fingerprint = "11babf42c472ea33ad2dbb9244d713b2e76d610909cd8dffc467ae22a92f2e4a"
        creation_date = "2023-10-30"
        last_modified = "2026-01-06"
        threat_name = "Windows.Trojan.Guloader"
        reference = "https://www.elastic.co/security-labs/getting-gooey-with-guloader-downloader"
        reference_sample = "6ae7089aa6beaa09b1c3aa3ecf28a884d8ca84f780aab39902223721493b1f99"
        severity = 100
        arch_context = "x86, arm64"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $djb2_str_compare = { 83 C0 08 83 3C 04 00 0F 84 [4] 39 14 04 75 }
        $check_exception = { 8B 45 ?? 8B 00 38 EC 8B 58 ?? 84 FD 81 38 05 00 00 C0 }
        $parse_mem = { 18 00 10 00 00 83 C0 18 50 83 E8 04 81 00 00 10 00 00 50 }
        $hw_bp = { 39 48 0C 0F 85 [4] 39 48 10 0F 85 [4] 39 48 14 0F 85 [7] 39 48 18 }
    condition:
        2 of them
}