rule Windows_Generic_MalCert_21c05181 {
    meta:
        author = "Elastic Security"
        id = "21c05181-7532-449e-a8da-96cd216c5241"
        fingerprint = "87413a7739d8de920c583c5b7ba42409014f4d3f2bd8170a22722d6c9a556cae"
        creation_date = "2025-02-05"
        last_modified = "2025-02-10"
        threat_name = "Windows.Generic.MalCert"
        reference_sample = "598d2e71d2aa01e03aeb2ad1ef037ad5489f3bce1e1bde0a3e05d73565f5955b"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $a1 = { 01 02 02 0C 20 52 32 B8 64 FC 3D 16 1B 07 33 A9 }
    condition:
        all of them
}