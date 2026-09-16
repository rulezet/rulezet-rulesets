rule Windows_Generic_MalCert_e507f27b {
    meta:
        author = "Elastic Security"
        id = "e507f27b-5c5a-4082-9270-7df5b47122ef"
        fingerprint = "6300d3bab1576ad5ab48ce1833cd5d6f10255510a1247fd5ab51f27d24c37b20"
        creation_date = "2025-02-05"
        last_modified = "2025-02-10"
        threat_name = "Windows.Generic.MalCert"
        reference_sample = "8b5af508dcee04dbb7dabdffeff03726ef821182ffdb8a930af57e9e71740440"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $a1 = { 01 02 02 0C 7A 06 2E 41 04 BF 96 33 E5 CD AC 31 }
    condition:
        all of them
}