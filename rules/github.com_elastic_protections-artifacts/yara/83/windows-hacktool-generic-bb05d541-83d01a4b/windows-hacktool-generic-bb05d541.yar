rule Windows_Hacktool_Generic_bb05d541 {
    meta:
        author = "Elastic Security"
        id = "bb05d541-def6-4921-b3d5-81b1c57a7af0"
        fingerprint = "ad8f9fe64183880bf471aa162b830c3916417b22eb4fbe572e0b6c85226799e9"
        creation_date = "2026-09-21"
        last_modified = "2026-09-28"
        threat_name = "Windows.Hacktool.Generic"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $str_1 = "wextract.pdb" wide fullword
        $str_3 = { 4C 8D 05 11 73 00 00 C7 44 24 34 04 01 00 00 48 8D 44 24 40 BA 04 01 00 00 4C 2B C0 48 8D 4C 24 40 }
        $seq_2 = { 48 8D 44 24 38 41 B9 19 00 02 00 45 33 C0 48 89 44 24 20 48 8D 15 47 22 00 00 }
    condition:
        all of them
}