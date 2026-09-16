rule Windows_Generic_MalCert_1c42f7ff {
    meta:
        author = "Elastic Security"
        id = "1c42f7ff-d20b-46a9-a055-b386b59e7e02"
        fingerprint = "5007c14fac7a4aedd5b430d9d800a1fd50cd3eed99ccaf6382f4539bcad1ad2a"
        creation_date = "2025-02-05"
        last_modified = "2025-02-10"
        threat_name = "Windows.Generic.MalCert"
        reference_sample = "1618bb5c1d7874a4083ab40eed1106ec24679a64e564752594964a998eb93dfd"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $a1 = { 01 02 02 10 3C C9 EF 0D FC 14 DB 49 96 6F 02 99 8B 69 32 FB }
    condition:
        all of them
}