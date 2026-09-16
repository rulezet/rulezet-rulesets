rule Windows_VulnDriver_Paramount_b64d94cb {
    meta:
        author = "Elastic Security"
        id = "b64d94cb-fb6d-497d-816d-f3c9519e4436"
        fingerprint = "5b44b9b8d5bedafa0138238fee42b2ca088c48785537386f31a36d510aee18ab"
        creation_date = "2026-05-22"
        last_modified = "2026-07-20"
        description = "Subject: Paramount Software UK Ltd"
        threat_name = "Windows.VulnDriver.Paramount"
        reference_sample = "e891526a0d3b9d8121657c55384e7c1a80ca96c9577cffb62681c700551ce0d6"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $subject_name = { 06 03 55 04 03 [2] 50 61 72 61 6D 6F 75 6E 74 20 53 6F 66 74 77 61 72 65 20 55 4B 20 4C 74 64 }
        $str1 = "psmounterex.pdb"
    condition:
        int16(uint32(0x3C) + 0x5c) == 0x0001 and $subject_name and $str1
}