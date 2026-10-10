rule Windows_Hacktool_Generic_bafe5bc4 {
    meta:
        author = "Elastic Security"
        id = "bafe5bc4-2216-4319-908b-09373585754f"
        fingerprint = "55df1ab3fc49b5a674c5b1fdc8b7612b38dcc10ffd01acab4f8245c4131f60d7"
        creation_date = "2026-09-21"
        last_modified = "2026-09-28"
        threat_name = "Windows.Hacktool.Generic"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $seq_1 = { 83 65 FC 00 6A 00 68 80 00 00 00 6A 03 6A 00 6A 01 68 00 00 00 80 FF 75 08 FF 15 08 60 41 00 }
        $usage = "[ usage: xbin <exe> <section name>" ascii fullword
        $msg_object = "[ Looks like an object file" ascii fullword
        $msg_raw = "%8X file pointer to raw data (%08X to %08X)" ascii fullword
        $msg_nt = "  [ invalid nt header" ascii fullword
    condition:
        4 of them
}