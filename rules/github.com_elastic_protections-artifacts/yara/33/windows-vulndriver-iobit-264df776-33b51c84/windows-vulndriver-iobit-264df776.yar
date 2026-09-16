rule Windows_VulnDriver_IObit_264df776 {
    meta:
        author = "Elastic Security"
        id = "264df776-8682-434b-8237-7724a81b38a4"
        fingerprint = "3cb67a7211963db14232a9d42325bd17e0145ba83339f64001f7c3d48a4c0bbb"
        creation_date = "2026-05-22"
        last_modified = "2026-07-20"
        description = "Subject: IObit Information Technology"
        threat_name = "Windows.VulnDriver.IObit"
        reference_sample = "11bc55c0771d692279298211c1d434c04168e7c7f7c4328bfd600215b88c819b"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $subject_name = { 06 03 55 04 03 [2] 49 4F 62 69 74 20 49 6E 66 6F 72 6D 61 74 69 6F 6E 20 54 65 63 68 6E 6F 6C 6F 67 79 }
        $str1 = "IObitUnlocker.pdb"
    condition:
        int16(uint32(0x3C) + 0x5c) == 0x0001 and $subject_name and $str1
}