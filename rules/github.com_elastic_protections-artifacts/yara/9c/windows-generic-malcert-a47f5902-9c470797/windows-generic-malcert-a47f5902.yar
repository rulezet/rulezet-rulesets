rule Windows_Generic_MalCert_a47f5902 {
    meta:
        author = "Elastic Security"
        id = "a47f5902-d6be-4713-87ca-384cdd012a0b"
        fingerprint = "d1cb1c9167f1f6c04c6c96a1a47e1e4f58148c602f7fbeee80d5c70f3328fd51"
        creation_date = "2025-02-05"
        last_modified = "2025-02-10"
        threat_name = "Windows.Generic.MalCert"
        reference_sample = "313d6d6e9ba8e2335689b4993b14e90beba6ed0cf859f842a5d625036703e015"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $a1 = { 01 02 02 10 37 E2 F1 6D 1C 64 39 E4 52 9D 9E E4 80 93 FA 38 }
    condition:
        all of them
}