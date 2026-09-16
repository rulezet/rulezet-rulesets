rule Windows_Generic_MalCert_ec4381c9 {
    meta:
        author = "Elastic Security"
        id = "ec4381c9-abbb-4faa-8655-38204b267a3e"
        fingerprint = "83e27f8dc8dc38dfb4fea9f506065008098a44a6236717ba341f02e23aebbacc"
        creation_date = "2025-02-05"
        last_modified = "2025-02-10"
        threat_name = "Windows.Generic.MalCert"
        reference_sample = "6b0ce8e6ccab57ece76302b1c9ab570336f63bae4d11137ccf0b662fa323a457"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $a1 = { 01 02 02 0C 4D 60 69 B5 05 25 63 39 49 C1 2B 22 }
    condition:
        all of them
}