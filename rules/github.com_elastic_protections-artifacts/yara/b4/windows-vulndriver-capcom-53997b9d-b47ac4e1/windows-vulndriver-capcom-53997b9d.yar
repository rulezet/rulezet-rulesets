rule Windows_VulnDriver_Capcom_53997b9d {
    meta:
        author = "Elastic Security"
        id = "53997b9d-aa8c-438a-8037-2185d472857b"
        fingerprint = "92fda7050b0181a90aa3155a2979d349fc9061c97b4a9228b5c466a05ed1ddf2"
        creation_date = "2026-07-25"
        last_modified = "2026-08-11"
        description = "Subject: NAMCO BANDAI Online Inc."
        threat_name = "Windows.VulnDriver.Capcom"
        reference_sample = "7ec93f34eb323823eb199fbf8d06219086d517d0e8f4b9e348d7afd41ec9fd5d"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $subject_name = { 06 03 55 04 03 [2] 4E 41 4D 43 4F 20 42 41 4E 44 41 49 20 4F 6E 6C 69 6E 65 20 49 6E 63 2E }
        $str1 = "<<<Obsolete>>"
        $seq1 = { 0F B7 0A 66 41 C1 E1 02 44 8B D1 66 44 03 CF 41 C1 EA 06 41 8D 42 FF 83 F8 02 77 56 41 32 C9 66 33 C0 40 2A CF 41 2A CA 66 83 E1 3F 66 83 F9 0A 73 05 8D 41 30 EB 09 }
    condition:
        int16(uint32(0x3C) + 0x5c) == 0x0001 and int16(uint32(0x3C) + 0x18) == 0x020b and $subject_name and $str1 and $seq1
}