rule Windows_Generic_MalCert_65514fe0 {
    meta:
        author = "Elastic Security"
        id = "65514fe0-9474-40eb-b899-1a2c608e5185"
        fingerprint = "9ba77d6e02e11f632faf36a35fbe45ca2b5deec62eaa11df43e1c83d78426c4f"
        creation_date = "2025-02-05"
        last_modified = "2025-02-10"
        threat_name = "Windows.Generic.MalCert"
        reference_sample = "0c5a1ab9360a9df7bc8d3fe9d8570e43aed3fd2d3ae91dab0ba045dd03e47e83"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $a1 = { 01 02 02 10 08 D4 BF 5A 52 9C 72 59 97 E0 F6 C5 26 49 5D 2F }
    condition:
        all of them
}