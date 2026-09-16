rule Windows_Generic_MalCert_c14990fa {
    meta:
        author = "Elastic Security"
        id = "c14990fa-a441-4e0a-a05a-305abf46a891"
        fingerprint = "16703bc45d5fb7c18b6195483c611878c32fc0a853151ef0a4e75dadaee9b231"
        creation_date = "2025-02-05"
        last_modified = "2025-02-10"
        threat_name = "Windows.Generic.MalCert"
        reference_sample = "ce4498bb0e9d8ff33ec55a521c0ba64c7d5ea8c45927496109a42dfcaf4b9ce4"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $a1 = { 01 02 02 10 08 3F 4C 45 67 8D 2C 9C 7E A1 06 C9 00 03 B6 13 }
    condition:
        all of them
}