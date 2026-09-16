rule Windows_Generic_MalCert_f32fdfcb {
    meta:
        author = "Elastic Security"
        id = "f32fdfcb-84f5-43c3-95a3-20bbe61c5dcc"
        fingerprint = "921e6fb10f1ef8719cb7b29f15b15b50cf65c5e21e55f5936089b9f53ea3e931"
        creation_date = "2025-02-05"
        last_modified = "2025-02-10"
        threat_name = "Windows.Generic.MalCert"
        reference_sample = "9c322e9a3500cf1cc38eecdd7952422f592551b9cd5493045d729d50de181a12"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $a1 = { 01 02 02 10 3C 0C DC E0 B2 56 10 11 DB 47 BC 01 1C 6D 7D EA }
    condition:
        all of them
}