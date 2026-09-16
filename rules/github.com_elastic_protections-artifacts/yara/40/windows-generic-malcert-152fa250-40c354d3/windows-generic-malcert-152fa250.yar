rule Windows_Generic_MalCert_152fa250 {
    meta:
        author = "Elastic Security"
        id = "152fa250-c1c7-4905-ac22-e4cdc6af9723"
        fingerprint = "356a6c2759878382eeef1c01b2027452bfa2ee3a495a1b8d10301a5f0a9da8e7"
        creation_date = "2025-02-05"
        last_modified = "2025-02-10"
        threat_name = "Windows.Generic.MalCert"
        reference_sample = "5ded120267643bc09f3c66a9d64165c215d8f74b1b9b398b7864d1f61fbcfbdf"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $a1 = { 01 02 02 10 14 C0 AF 4E AB D0 5E 63 C3 D4 B3 38 E0 BF B7 E3 }
    condition:
        all of them
}