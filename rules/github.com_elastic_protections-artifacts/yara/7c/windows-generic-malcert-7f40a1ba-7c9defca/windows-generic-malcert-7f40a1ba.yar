rule Windows_Generic_MalCert_7f40a1ba {
    meta:
        author = "Elastic Security"
        id = "7f40a1ba-3fab-43fc-8581-6628065549ac"
        fingerprint = "5d3bde9de4418f94ea3395593e62f2643315ea9f078208d0481a963ff2d37e96"
        creation_date = "2025-02-05"
        last_modified = "2025-02-10"
        threat_name = "Windows.Generic.MalCert"
        reference_sample = "88eb72267896a9db69457a9400979772413f3208a41e6cf059c442de719bf98f"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $a1 = { 01 02 02 11 00 DC C8 1E F1 94 27 B6 B6 2B 71 7E 6E 92 EC 28 13 }
    condition:
        all of them
}