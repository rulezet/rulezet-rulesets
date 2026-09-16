rule Linux_Trojan_Generic_5e3bc3b3 {
    meta:
        author = "Elastic Security"
        id = "5e3bc3b3-c708-49dd-80c6-0d353acb4b53"
        fingerprint = "cf1c66af92607d0ec76ec1db0292fcb8035bdc85117dc714bdade32740d5a835"
        creation_date = "2024-09-20"
        description = "Rule for custom Trojan found in Linux REF6138."
        last_modified = "2024-11-04"
        threat_name = "Linux.Trojan.Generic"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $enc1 = { 74 73 0A 1C 1A 54 1A 11 54 0C 18 43 59 5B 3A 11 0B 16 14 10 0C 14 5B }
        $enc2 = { 18 1A 1A 1C 09 0D 43 59 0D 1C 01 0D 56 11 0D 14 15 55 18 09 09 15 10 }
        $enc3 = { 18 1A 1A 1C 09 0D 54 15 18 17 1E 0C 18 1E 1C 43 59 0B 0C }
        $enc4 = { 34 16 03 10 15 15 18 56 4C 57 49 59 51 2E 10 17 1D 16 0E 0A 59 37 }
        $key = "yyyyyyyy"
    condition:
        1 of ($enc*) and $key
}