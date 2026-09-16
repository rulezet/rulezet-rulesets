rule Windows_Generic_MalCert_d743cb47 {
    meta:
        author = "Elastic Security"
        id = "d743cb47-c046-4d3b-b04d-88e8486d8dbf"
        fingerprint = "be810e0016325fcd7e58aee9ea26062052b56397f1877cf94e7dc94a40a98f17"
        creation_date = "2025-02-05"
        last_modified = "2025-02-10"
        threat_name = "Windows.Generic.MalCert"
        reference_sample = "70668430bda8e76026d01964200fdb93ae276e9af15d202613aec97107573c6d"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $a1 = { 01 02 02 0C 3C 56 D6 27 7A 99 7F D1 D7 80 87 32 }
    condition:
        all of them
}