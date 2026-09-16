rule Windows_Generic_MalCert_33d0a7b5 {
    meta:
        author = "Elastic Security"
        id = "33d0a7b5-9280-450b-83a7-1737fad61e42"
        fingerprint = "79d6f041d933100c640aa7775a9862375baab351308f3492e182c47b24846bb1"
        creation_date = "2025-02-05"
        last_modified = "2025-02-10"
        threat_name = "Windows.Generic.MalCert"
        reference_sample = "67ebe950959d5c68b5d1423504d1aed80d38e0bfaf11943bb0a4b7303142e0ed"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $a1 = { 01 02 02 10 77 FE CF 9E 4D D9 53 10 06 4F CB 0E 42 81 0C 06 }
    condition:
        all of them
}