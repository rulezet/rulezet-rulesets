rule Windows_Rootkit_Generic_740b1440 {
    meta:
        author = "Elastic Security"
        id = "740b1440-b4bd-4f7f-bdf0-a06fd85ddc5f"
        fingerprint = "494f1f6e4920b78e21aff2db98f400388f74724c76ec5d44ebdce169ba378a6a"
        creation_date = "2026-07-21"
        last_modified = "2026-08-11"
        threat_name = "Windows.Rootkit.Generic"
        reference_sample = "4473fef2a90a3217db685de44f575d2586666fcf3db7fa9efa1328afcdbf34a8"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $str1 = "\\DosDevices\\isj2uaoX" wide
        $str2 = "C:\\Intel\\x"
        $seq1 = { 48 8D 50 30 48 F7 D8 48 1B C0 48 23 C2 48 3B 47 08 75 06 8B 47 10 89 43 08 48 8B 5C 24 30 32 C0 48 83 C4 20 }
    condition:
        int16(uint32(0x3C) + 0x5c) == 0x0001 and int16(uint32(0x3C) + 0x18) == 0x020b and $str1 and $str2 and $seq1
}