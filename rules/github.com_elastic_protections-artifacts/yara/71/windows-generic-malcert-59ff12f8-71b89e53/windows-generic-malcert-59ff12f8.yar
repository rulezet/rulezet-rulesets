rule Windows_Generic_MalCert_59ff12f8 {
    meta:
        author = "Elastic Security"
        id = "59ff12f8-eac5-47bc-a168-f2db92d56698"
        fingerprint = "b12bba9e0ef3d0bea8e73f6e8773db0a9545b8fd144e51eee3e273cca8962ada"
        creation_date = "2025-02-05"
        last_modified = "2025-02-10"
        threat_name = "Windows.Generic.MalCert"
        reference_sample = "f645d0f75ce7f1256c64cd7c52fbd2cc4cafb7ae1b30c39e73907fa01b8079da"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $a1 = { 01 02 02 10 74 67 20 93 D7 30 4A 14 8F 79 47 AD ED F8 99 86 }
    condition:
        all of them
}