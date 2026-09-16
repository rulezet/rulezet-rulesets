rule Windows_Generic_MalCert_ad55864e {
    meta:
        author = "Elastic Security"
        id = "ad55864e-ce44-436d-93dc-fdf6217a6897"
        fingerprint = "498e32f7e71b9d615e481ce7070e59c6d051c6dd753331e0087b54ee4ffc3919"
        creation_date = "2025-02-05"
        last_modified = "2025-02-10"
        threat_name = "Windows.Generic.MalCert"
        reference_sample = "654636d8d996e7aa93e93581f595bf63d32a3fd18c6b84d5c3b31de113fc1740"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $a1 = { 01 02 02 10 23 10 78 28 3B AC 1A 1A 90 F6 42 02 E8 41 77 AD }
    condition:
        all of them
}