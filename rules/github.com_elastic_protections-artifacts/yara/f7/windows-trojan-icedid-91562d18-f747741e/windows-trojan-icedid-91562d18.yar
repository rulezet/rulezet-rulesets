rule Windows_Trojan_IcedID_91562d18 {
    meta:
        author = "Elastic Security"
        id = "91562d18-28a1-4349-9e4b-92ad165510c9"
        fingerprint = "024bbd15da6bc759e321779881b466b500f6364a1d67bbfdc950aedccbfbc022"
        creation_date = "2022-04-06"
        last_modified = "2022-06-09"
        threat_name = "Windows.Trojan.IcedID"
        reference = "https://www.elastic.co/security-labs/thawing-the-permafrost-of-icedid-summary"
        reference_sample = "b9fb0a4c28613c556fb67a0b0e7c9d4c1236b60a161ad935e7387aec5911413a"
        severity = 100
        arch_context = "x86, arm64"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $a = { 44 8B 4C 19 2C 4C 03 D6 74 1C 4D 85 C0 74 17 4D 85 C9 74 12 41 }
    condition:
        all of them
}