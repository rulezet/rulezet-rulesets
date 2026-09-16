rule Windows_Trojan_WarmCookie_344e4d3f {
    meta:
        author = "Elastic Security"
        id = "344e4d3f-55fb-4ad3-893b-32bd2ce50a06"
        fingerprint = "31f78ec5c1816e32e29e505d5d4980ebe7321652b22c2e77e14d205dd8941207"
        creation_date = "2025-02-26"
        last_modified = "2025-05-27"
        threat_name = "Windows.Trojan.WarmCookie"
        reference = "https://www.elastic.co/security-labs/dipping-into-danger"
        reference_sample = "46733541444536d7b64d25e709f1432eb844569eb7473800c2f1998617022d15"
        severity = 100
        arch_context = "x86, arm64"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $seq1 = { B9 E8 03 00 00 FF 15 }
        $seq2 = { B9 10 27 00 00 FF 15 A2 D0 00 00 }
        $seq3 = { 3D B7 00 00 00 74 16 }
        $seq4 = { C7 84 24 74 02 00 00 A0 05 00 00 }
        $seq5 = { BE 1C 00 00 00 81 7C 24 5C EF 55 00 00 }
    condition:
        4 of them
}