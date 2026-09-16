rule Windows_VulnDriver_Rootkit_06e4d47e {
    meta:
        author = "Elastic Security"
        id = "06e4d47e-8db9-4e95-9fea-b13e9666c646"
        fingerprint = "6efa09308a4142a11b89e243258cd9192768e7c030b64cb4fad797ff4861c1ea"
        creation_date = "2026-05-22"
        last_modified = "2026-07-29"
        description = "Subject: WDKTestCert anash,133231280654008727"
        threat_name = "Windows.VulnDriver.Rootkit"
        reference_sample = "0ae8d1dd56a8a000ced74a627052933d2e9bff31d251de185b3c0c5fc94a44db"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $subject_name = { 06 03 55 04 03 [2] 57 44 4B 54 65 73 74 43 65 72 74 20 61 6E 61 73 68 2C 31 33 33 32 33 31 32 38 30 36 35 34 30 30 38 37 32 37 }
        $str1 = "Chaos-Rootkit.pdb"
    condition:
        int16(uint32(0x3C) + 0x5c) == 0x0001 and int16(uint32(0x3C) + 0x18) == 0x020b and $subject_name and $str1
}