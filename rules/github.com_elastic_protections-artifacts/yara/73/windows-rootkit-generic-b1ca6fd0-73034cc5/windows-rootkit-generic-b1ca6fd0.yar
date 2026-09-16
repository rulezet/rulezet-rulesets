rule Windows_Rootkit_Generic_b1ca6fd0 {
    meta:
        author = "Elastic Security"
        id = "b1ca6fd0-3651-4ec0-a1b0-c54642d05166"
        fingerprint = "a34bb722a914ab1646535f4de55c81b94e5906e3145b693bff139bce386c5cc4"
        creation_date = "2026-07-25"
        last_modified = "2026-08-11"
        description = ""
        threat_name = "Windows.Rootkit.Generic"
        reference_sample = "c1c4310e5d467d24e864177bdbfc57cb5d29aac697481bfa9c11ddbeebfd4cc8"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $str1 = "Z:\\NewProjects\\hide_tools\\objfre\\i386\\hidetools.pdb"
        $str2 = "\\registry\\machine\\system\\CurrentControlSet\\Enum\\Root\\LEGACY_%ws" wide
        $seq1 = { 8B 46 04 43 83 E8 08 43 FF 45 08 D1 E8 39 45 08 72 C7 03 76 04 EB A1 }
    condition:
        int16(uint32(0x3C) + 0x5c) == 0x0001 and $str1 and $str2 and $seq1
}