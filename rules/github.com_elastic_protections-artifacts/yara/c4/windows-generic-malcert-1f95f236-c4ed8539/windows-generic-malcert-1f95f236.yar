rule Windows_Generic_MalCert_1f95f236 {
    meta:
        author = "Elastic Security"
        id = "1f95f236-7069-4764-b3b1-e7e17f2e97b7"
        fingerprint = "77da46797fcd563e504f780c4b2622e780aa24d2dc4f243cdcad650e53fa748e"
        creation_date = "2025-02-05"
        last_modified = "2025-02-10"
        threat_name = "Windows.Generic.MalCert"
        reference_sample = "7e99bbab3a4b51999bfd80de8e8f5ecd4d1098757cb0f00202503fa7179c3a08"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $a1 = { 01 02 02 10 7F 89 B1 89 5D 7F 80 BD 14 C2 73 B8 7A 75 03 89 }
    condition:
        all of them
}