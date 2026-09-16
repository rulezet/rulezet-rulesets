rule Windows_Generic_MalCert_afe226f4 {
    meta:
        author = "Elastic Security"
        id = "afe226f4-ac89-4c2d-b607-4fe1f94efc72"
        fingerprint = "cc6655d96362d6d25064b2a959691c66bb66bca3a9c05fe6e19a8d52157ae251"
        creation_date = "2025-02-05"
        last_modified = "2025-02-10"
        threat_name = "Windows.Generic.MalCert"
        reference_sample = "3b66d49496a185b70e9f4a4681eca1e0f8a0d00fdff4f4f735b8c4232f65fb95"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $a1 = { 01 02 02 0C 21 39 10 E0 20 B1 96 D0 A9 D3 53 B4 }
    condition:
        all of them
}