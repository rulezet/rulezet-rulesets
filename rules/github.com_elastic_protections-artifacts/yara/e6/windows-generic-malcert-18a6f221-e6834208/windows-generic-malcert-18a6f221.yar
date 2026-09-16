rule Windows_Generic_MalCert_18a6f221 {
    meta:
        author = "Elastic Security"
        id = "18a6f221-f688-44a1-a964-1834fb650315"
        fingerprint = "039d864425d19dbd5ad3c36e2a44ae525cc767b7510be5f892e7435759212ce6"
        creation_date = "2025-02-05"
        last_modified = "2025-02-10"
        threat_name = "Windows.Generic.MalCert"
        reference_sample = "c2614d4f0aeadbdf1cc6efbe9116f7e80393eb560e7cc96f5f0c2300f002d806"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $a1 = { 01 02 02 10 5D 02 53 3E 72 14 B0 42 D0 2D C0 FB D0 B7 C0 74 }
    condition:
        all of them
}