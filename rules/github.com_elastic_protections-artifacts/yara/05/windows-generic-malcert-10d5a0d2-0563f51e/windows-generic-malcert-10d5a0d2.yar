rule Windows_Generic_MalCert_10d5a0d2 {
    meta:
        author = "Elastic Security"
        id = "10d5a0d2-cdc8-4ebd-9fe9-9a3fd7e6bf1b"
        fingerprint = "cc199dcb5ca8e6f46cf5b40ca4331f7907d871472fca5aec0f3a9188da3712f8"
        creation_date = "2025-02-05"
        last_modified = "2025-02-10"
        threat_name = "Windows.Generic.MalCert"
        reference_sample = "c974933dd65a10d51f07f1c1bbd034e1357193fa70cf51d3cbe03f8752aa0594"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $a1 = { 01 02 02 10 0A 7F 68 D7 A3 C7 8A 2A 05 25 EF 97 37 EA B8 81 }
    condition:
        all of them
}