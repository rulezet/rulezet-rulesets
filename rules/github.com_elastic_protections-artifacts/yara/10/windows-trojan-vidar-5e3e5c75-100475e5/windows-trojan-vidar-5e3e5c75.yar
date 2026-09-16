rule Windows_Trojan_Vidar_5e3e5c75 {
    meta:
        author = "Elastic Security"
        id = "5e3e5c75-00a6-4dca-ac29-1a4d3554b9bd"
        fingerprint = "6a21d58bd025d08b40c64fd38df8af637bc97938b268143427aaa96c79a8caa7"
        creation_date = "2025-12-16"
        last_modified = "2026-02-02"
        threat_name = "Windows.Trojan.Vidar"
        reference_sample = "0f8976f8b0f6f717ffdfb22cfc1620eee53ce462975bb270929bff3497d22beb"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $a = "%DRIVE_FIXED%" fullword
        $e = "%DRIVE_REMOVABLE%" fullword
        $d = "_0.indexeddb.leveldb" fullword
        $c = "key4.db" fullword
    condition:
        all of them
}