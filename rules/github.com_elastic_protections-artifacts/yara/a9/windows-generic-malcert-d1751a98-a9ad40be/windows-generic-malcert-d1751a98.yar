rule Windows_Generic_MalCert_d1751a98 {
    meta:
        author = "Elastic Security"
        id = "d1751a98-27f5-4a5d-bc73-b6bfebe37c0f"
        fingerprint = "34744efb4a21e8b22ecb3cdced7746b216cb511899b9fa25e7e81438c2a5b9e1"
        creation_date = "2025-02-05"
        last_modified = "2025-02-10"
        threat_name = "Windows.Generic.MalCert"
        reference_sample = "9959fc6e686d668f8e5e2f3935b6e8c86b547150acaaf8d9687de4fa4d1c937c"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $a1 = { 01 02 02 0C 7D 2C 9D 9D EE F3 AA C2 1C 89 59 76 }
    condition:
        all of them
}