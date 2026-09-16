rule Windows_Generic_MalCert_578f96d1 {
    meta:
        author = "Elastic Security"
        id = "578f96d1-7dba-4199-ac35-8726af705230"
        fingerprint = "357041128d835a1af6b345988e52bb19d39bb5654b81587574a50fca2cfdc25a"
        creation_date = "2025-02-05"
        last_modified = "2025-02-10"
        threat_name = "Windows.Generic.MalCert"
        reference_sample = "eeb8cb6bc1340b2fa84a2d79ae68c001e05caae3be5c446220dcef5da9579d06"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $a1 = { 01 02 02 11 00 C0 E2 8F 6B F3 D8 D0 CC 00 30 6D F9 02 D6 EC 0F }
    condition:
        all of them
}