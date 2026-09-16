rule Windows_Generic_MalCert_b650c953 {
    meta:
        author = "Elastic Security"
        id = "b650c953-0273-4e25-af00-110f76542372"
        fingerprint = "6d32dc006e2e32d13fa3ee7367ce1d187b5cbb4d7055c0e5119a93746dd5f06d"
        creation_date = "2025-02-05"
        last_modified = "2025-02-10"
        threat_name = "Windows.Generic.MalCert"
        reference_sample = "ceb75880148e05af7e9d029ee11d33535346ff5161b2bc506dbadd710688b9f3"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $a1 = { 01 02 02 10 20 E6 5F 5D 29 B5 82 24 10 50 4B 1A C1 83 CA 3D }
    condition:
        all of them
}