rule Windows_Generic_MalCert_2a954560 {
    meta:
        author = "Elastic Security"
        id = "2a954560-18c1-4f67-b614-92e153aa6c85"
        fingerprint = "17543b7278aa9ad89aef7ae206e0df2d913ced96bd577703be9a91bc3a47b818"
        creation_date = "2025-02-05"
        last_modified = "2025-02-10"
        threat_name = "Windows.Generic.MalCert"
        reference_sample = "fbd914b7d9019785d62c25ad164901752c5587c0847e32598e66fa25b6cf23cb"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $a1 = { 01 02 02 10 77 E1 B3 58 54 DF A9 8B 97 02 C7 F4 C4 FE D6 0D }
    condition:
        all of them
}