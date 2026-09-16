rule Windows_Generic_MalCert_35a7e8aa {
    meta:
        author = "Elastic Security"
        id = "35a7e8aa-2081-417d-be44-419fc29b70c4"
        fingerprint = "7ec3106a9323a5e2542ffb31b5fe61e274d5d1179867b897e16c453f95bde959"
        creation_date = "2025-02-05"
        last_modified = "2025-02-10"
        threat_name = "Windows.Generic.MalCert"
        reference_sample = "cfb5cb22b2b882d620507a88942a4bfe66fd65082b918b1b9a6699fd56ac5a9d"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $a1 = { 01 02 02 0C 50 5F 39 51 5D A5 58 18 23 24 C2 CA }
    condition:
        all of them
}