rule Windows_Generic_MalCert_9262df80 {
    meta:
        author = "Elastic Security"
        id = "9262df80-4e82-43e2-b21f-e509aced0caf"
        fingerprint = "4fdb73a01e709bb48baf79c91e0eb8d212d8ef213b18666f738df71b5e24a199"
        creation_date = "2025-02-05"
        last_modified = "2025-02-10"
        threat_name = "Windows.Generic.MalCert"
        reference_sample = "86e966dacad8d808ba568d9dc53eeffb4e8848fa8eb9516e97c13bed8317b814"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $a1 = { 01 02 02 0C 51 09 AE 83 71 B0 50 7A 4D 72 42 5C }
    condition:
        all of them
}