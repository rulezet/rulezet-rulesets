rule Linux_Ransomware_Akira_27440619 {
    meta:
        author = "Elastic Security"
        id = "27440619-50de-4103-b961-6b66cf9001f9"
        fingerprint = "611b051982db94dc83a875b3e5ae20177690fda16ead5b8591cb12d0e899712b"
        creation_date = "2024-11-21"
        last_modified = "2024-11-22"
        threat_name = "Linux.Ransomware.Akira"
        reference_sample = "3298d203c2acb68c474e5fdad8379181890b4403d6491c523c13730129be3f75"
        severity = 100
        arch_context = "x86, arm64"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a = { 41 83 A7 00 01 00 00 00 31 C0 41 88 87 04 01 00 00 6A 08 5B 49 89 9F 08 01 00 00 0F 57 C0 41 0F 29 87 10 01 00 00 49 89 9F 20 01 00 00 41 0F 11 87 28 01 00 00 41 C6 87 38 01 00 00 01 6A 01 41 5E }
    condition:
        all of them
}