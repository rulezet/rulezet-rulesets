rule Windows_Generic_MalCert_30719a7d {
    meta:
        author = "Elastic Security"
        id = "30719a7d-7a20-490d-ac45-1a721c313667"
        fingerprint = "085c588bf642cb66db9401a5cc07eb60e527bcf6eb1da443a300fe98b37445a9"
        creation_date = "2025-02-05"
        last_modified = "2025-02-10"
        threat_name = "Windows.Generic.MalCert"
        reference_sample = "7822ff888410631fe2844b3c843319e9d135a32b75ecd497c3f91ec68c5b9825"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $a1 = { 01 02 02 10 79 D0 57 D5 AB 18 35 B2 0E 55 27 FC F1 01 92 CC }
    condition:
        all of them
}