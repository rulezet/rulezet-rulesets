rule Windows_Generic_MalCert_b5f08eaf {
    meta:
        author = "Elastic Security"
        id = "b5f08eaf-9a9a-4144-8c5e-b17fddcbcfba"
        fingerprint = "95beb777140dd964880c0db5839a7437f68a8ca11a0eceeb0aa1cb99841d33e9"
        creation_date = "2025-02-05"
        last_modified = "2025-02-10"
        threat_name = "Windows.Generic.MalCert"
        reference_sample = "553e275198061d8c0d35ce89ac083909f12091ed761b8977700548bc968b137a"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $a1 = { 01 02 02 10 63 1A 2A 12 F9 3A A1 2F 79 34 D0 7A 16 A6 54 16 }
    condition:
        all of them
}