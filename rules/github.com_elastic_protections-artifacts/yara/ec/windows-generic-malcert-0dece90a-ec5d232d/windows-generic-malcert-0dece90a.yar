rule Windows_Generic_MalCert_0dece90a {
    meta:
        author = "Elastic Security"
        id = "0dece90a-6870-4436-a456-6798a7b9b7b1"
        fingerprint = "6fd4830173029476f19e558cfcd154dca5adfb637606e6f8da1fe30c0fcddeaf"
        creation_date = "2025-02-05"
        last_modified = "2025-02-10"
        threat_name = "Windows.Generic.MalCert"
        reference_sample = "2bc61416837f467bb8560d3a39b14d755f1c9f003254e74cc635e8ff6a00626a"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $a1 = { 01 02 02 10 38 7C 94 76 E2 83 20 26 45 94 84 63 17 D4 65 40 }
    condition:
        all of them
}