rule Windows_Generic_MalCert_724bed8d {
    meta:
        author = "Elastic Security"
        id = "724bed8d-6230-4184-a148-e3960a23fe52"
        fingerprint = "db56343a197d81ae24f26695e4d1d07a9defeb9f571a3b5070b9ee18aedd4a9e"
        creation_date = "2025-02-05"
        last_modified = "2025-02-10"
        threat_name = "Windows.Generic.MalCert"
        reference_sample = "850c3e89c9d98b978e03a837eb24e48ed85b495ca486660016f51f3f41712611"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $a1 = { 01 02 02 0C 0E EB 82 9E EB 4B 17 CB 6C ED 4F 42 }
    condition:
        all of them
}