rule Windows_Generic_MalCert_a775b53a {
    meta:
        author = "Elastic Security"
        id = "a775b53a-ff41-4377-9c71-2cca9ce02048"
        fingerprint = "23cd01190ed48bf05d69e92b3a00fce7f008ea7f2b5f3d2ee860ffb6a7a45589"
        creation_date = "2025-02-05"
        last_modified = "2025-02-10"
        threat_name = "Windows.Generic.MalCert"
        reference_sample = "d38fce27eafc1a8eb4c83cd043fe2494e5c9a4939ff3a2784ca43beb8839bb3a"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $a1 = { 01 02 02 0C 28 E8 92 43 4E 59 E2 52 41 3D 3E 0E }
    condition:
        all of them
}