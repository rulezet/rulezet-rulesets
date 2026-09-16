rule Windows_Generic_MalCert_21673599 {
    meta:
        author = "Elastic Security"
        id = "21673599-68e5-4a74-ba77-2d2356561caa"
        fingerprint = "813227294fe904a8073a0a2f8bab534c73def88d46d6db5d8db3c27484160bfb"
        creation_date = "2025-02-05"
        last_modified = "2025-02-10"
        threat_name = "Windows.Generic.MalCert"
        reference_sample = "804641f152a3e6994e05e316224a5c8f790a2de5681dd78fa85674152e74677a"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $a1 = { 01 02 02 10 1B 3C 13 05 D4 95 D4 9D 68 C7 C0 18 58 3F 25 31 }
    condition:
        all of them
}