rule Windows_Generic_MalCert_1abaf391 {
    meta:
        author = "Elastic Security"
        id = "1abaf391-b148-4d56-b5c5-2d78ef6e98cf"
        fingerprint = "59f04af52c1060795286dd7e229cf3cbfd81f38d8db52eeb417792bd73636e1d"
        creation_date = "2025-02-05"
        last_modified = "2025-02-10"
        threat_name = "Windows.Generic.MalCert"
        reference_sample = "37c903910f91654c1a68751cd3b4dd6adc1fdd3477bfb576081b2672be39f3e9"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $a1 = { 01 02 02 10 6A 0D 76 08 17 D8 72 18 99 B4 FB CE F1 56 9D F1 }
    condition:
        all of them
}