rule Windows_Generic_MalCert_ab8661e1 {
    meta:
        author = "Elastic Security"
        id = "ab8661e1-7fc9-49b1-a314-657992fc0961"
        fingerprint = "8838e1f2210f6915622fc694e937cb5b80401b5643352d93dead4478d57c6a47"
        creation_date = "2025-02-05"
        last_modified = "2025-02-10"
        threat_name = "Windows.Generic.MalCert"
        reference_sample = "5b7aefe3a61be8dbc94b2f8f75ad479a93a04078f0f0b45ba6c86ab7eb12f911"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $a1 = { 01 02 02 0C 08 2B DD E2 74 00 8D CD FF 05 BA 08 }
    condition:
        all of them
}