rule Windows_Generic_MalCert_108e8774 {
    meta:
        author = "Elastic Security"
        id = "108e8774-ada3-4319-b713-1213eed8967e"
        fingerprint = "8d7dce4e3474faddfb6dbbd0d706162aed7244ac45d631194eb9be68a5318d06"
        creation_date = "2025-02-05"
        last_modified = "2025-02-10"
        threat_name = "Windows.Generic.MalCert"
        reference_sample = "ab21d23f3f642b1d4559df845052d50adce1e0bcc9a0fb88042e72f2791c3a30"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $a1 = { 01 02 02 10 0D E6 76 A4 C5 AF 15 BF B3 77 1C 14 2A CD A8 FD }
    condition:
        all of them
}