rule Windows_Generic_MalCert_321cda6e {
    meta:
        author = "Elastic Security"
        id = "321cda6e-ea2a-4c4b-b660-0245d24858db"
        fingerprint = "7f1f8511b57aa774518a16c47b708b53b828839beff6f445481d783abf7b31f7"
        creation_date = "2025-02-05"
        last_modified = "2025-02-10"
        threat_name = "Windows.Generic.MalCert"
        reference_sample = "567115a08d2eebcbdea89d83dd9a297020c360b3f99117b990eb3fe95501acc2"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $a1 = { 01 02 02 11 00 B7 D1 97 55 1A 90 91 8E C0 B3 20 F6 DA 64 B3 0D }
    condition:
        all of them
}