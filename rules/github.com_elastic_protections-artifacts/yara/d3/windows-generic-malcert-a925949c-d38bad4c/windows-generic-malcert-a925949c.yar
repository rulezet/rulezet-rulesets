rule Windows_Generic_MalCert_a925949c {
    meta:
        author = "Elastic Security"
        id = "a925949c-387d-403a-8a41-de5f0453764a"
        fingerprint = "a2a7c50ca9c703f0350e2b9cd1402634e22ca7dde9213227e3e7b5fb4144c8ea"
        creation_date = "2025-02-05"
        last_modified = "2025-02-10"
        threat_name = "Windows.Generic.MalCert"
        reference_sample = "c33ea2ccb5a6e4aef16cfb18f64c5e459ce09d7d7d5dc963697c496e61f54a91"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $a1 = { 01 02 02 0C 15 D2 21 01 46 49 44 AB 90 81 D4 0F }
    condition:
        all of them
}