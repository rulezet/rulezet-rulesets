rule Windows_Generic_MalCert_42e6a3ea {
    meta:
        author = "Elastic Security"
        id = "42e6a3ea-0d76-471c-8cd4-391124aa282d"
        fingerprint = "197ce5c581928092ed3a36b85b37172502ec5acf53beeb866aa50a2375875735"
        creation_date = "2025-02-05"
        last_modified = "2025-02-10"
        threat_name = "Windows.Generic.MalCert"
        reference_sample = "ebdd5efd08c7f68a57850f4967f259a1cd4acb035e5ca6bdfb64e22b17f3c671"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $a1 = { 01 02 02 10 07 53 C9 D0 B1 D9 AC 84 FD 84 DD BE E2 4D F8 92 }
    condition:
        all of them
}