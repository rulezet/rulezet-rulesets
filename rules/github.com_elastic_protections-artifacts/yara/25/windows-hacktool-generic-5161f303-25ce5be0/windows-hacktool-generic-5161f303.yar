rule Windows_Hacktool_Generic_5161f303 {
    meta:
        author = "Elastic Security"
        id = "5161f303-7e6c-44d7-8250-a37dc8bf5b91"
        fingerprint = "c8bc6dbff7f8fd1a97f3a55309a3f53df86691d0eda82f290dc09e4734b50481"
        creation_date = "2026-09-21"
        last_modified = "2026-09-28"
        threat_name = "Windows.Hacktool.Generic"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $str_1 = "Hello From Main...I Don't Do Anything" wide fullword
        $str_2 = "Hello There From Uninstall" wide fullword
        $str_3 = "I shouldn't really execute either." wide fullword
        $str_4 = "Allthingsdll_64.dll" fullword
    condition:
        3 of them
}