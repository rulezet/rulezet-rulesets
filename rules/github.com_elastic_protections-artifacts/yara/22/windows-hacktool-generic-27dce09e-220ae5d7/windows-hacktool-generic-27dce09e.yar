rule Windows_Hacktool_Generic_27dce09e {
    meta:
        author = "Elastic Security"
        id = "27dce09e-c774-4bbd-9b5c-88e6a6bcc668"
        fingerprint = "9c74c3db517b9aa6482fa7e97114ae69e3107db7f10cd6a38856915fd12dfb60"
        creation_date = "2026-09-21"
        last_modified = "2026-09-28"
        threat_name = "Windows.Hacktool.Generic"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $seq_1 = { 55 89 E5 83 EC 18 C7 44 24 04 01 00 00 00 C7 04 24 00 40 F8 61 A1 0C 71 F8 61 FF D0 83 EC 08 90 C9 }
        $str_1 = "beerTime"
    condition:
        all of them
}