rule Windows_Generic_MalCert_24178164 {
    meta:
        author = "Elastic Security"
        id = "24178164-6a9d-43b5-8b5d-372e17a87e4d"
        fingerprint = "119d5b11a5d7577074a7f52b6b7cedc2c6323778be13e2321021a0fbf6200cea"
        creation_date = "2025-02-05"
        last_modified = "2025-02-10"
        threat_name = "Windows.Generic.MalCert"
        reference_sample = "2074099eb6b722d430cbd953ec452984acb84e04c23ddf7e5c9393f906fd910d"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $a1 = { 01 02 02 0C 34 DE F8 02 47 9C 8F D6 3C 6A B6 A9 }
    condition:
        all of them
}