rule Windows_VulnDriver_Mimikatz_5a6e0ac2 {
    meta:
        author = "Elastic Security"
        id = "5a6e0ac2-7af3-4933-9e6d-920b24997be5"
        fingerprint = "2c50451836a6580f464642a35be2e89e9d3fbf8bd57a01c935236d9595f62756"
        creation_date = "2026-05-22"
        last_modified = "2026-07-20"
        description = "Subject: Benjamin Delpy"
        threat_name = "Windows.VulnDriver.Mimikatz"
        reference_sample = "083a311875173f8c4653e9bbbabb689d14aa86b852e7fa9f5512fc60e0fd2c43"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $subject_name = { 06 03 55 04 03 [2] 42 65 6E 6A 61 6D 69 6E 20 44 65 6C 70 79 }
        $str1 = "mimikatz.pdb"
    condition:
        int16(uint32(0x3C) + 0x5c) == 0x0001 and $subject_name and $str1
}