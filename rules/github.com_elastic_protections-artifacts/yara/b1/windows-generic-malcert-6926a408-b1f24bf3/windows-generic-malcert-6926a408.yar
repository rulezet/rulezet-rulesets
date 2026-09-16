rule Windows_Generic_MalCert_6926a408 {
    meta:
        author = "Elastic Security"
        id = "6926a408-caf2-4f07-8730-7aa58ff20e11"
        fingerprint = "6dd71678162cce3c9e0dc0646c67c6c6651cd4510e9eb22d7783cb2eef544c65"
        creation_date = "2025-02-05"
        last_modified = "2025-02-10"
        threat_name = "Windows.Generic.MalCert"
        reference_sample = "737916b4a5c2efd460eb4bf84dc4d01d505f1c0779a984e5471b2bc71582a545"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $a1 = { 01 02 02 10 50 57 28 6E 40 33 FC B0 00 00 00 00 55 65 F5 AC }
    condition:
        all of them
}