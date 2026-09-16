rule Windows_Generic_MalCert_d8ebed26 {
    meta:
        author = "Elastic Security"
        id = "d8ebed26-88e6-4360-864b-b43a4658c36e"
        fingerprint = "a02002ea866f7794bfa15855745400385f198a8b96f19bad8dce7c263b6214ad"
        creation_date = "2025-02-05"
        last_modified = "2025-02-10"
        threat_name = "Windows.Generic.MalCert"
        reference_sample = "51d03995f68aa54f065b4d23961de01392f9d584740932f6a32312ae2ff34304"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $a1 = { 01 02 02 10 79 E1 8F 9B 4E 7C AC 3F A1 1E B5 DF F6 A0 51 E0 }
    condition:
        all of them
}