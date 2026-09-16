rule Windows_VulnDriver_Capcom_7fff4461 {
    meta:
        author = "Elastic Security"
        id = "7fff4461-bb9d-41dd-bae1-f200f67523b1"
        fingerprint = "2df53b9a8593ffffdf2d32cceeec6433db93ca22638e6462a0f638ebd80957e1"
        creation_date = "2026-07-20"
        last_modified = "2026-08-11"
        description = ""
        threat_name = "Windows.VulnDriver.Capcom"
        reference_sample = "0c1b21978c6aef881f056f7b9c909b56488019459ed256511d78a4588d1aa7a4"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $seq_1 = { 48 53 56 57 48 83 EC 20 48 8B 82 B8 00 00 00 48 8B 7A 18 33 C9 89 4A 30 48 89 4A 38 80 38 0E 44 8B 48 10 44 8B 40 08 48 8B DA 8B 50 18 74 09 C7 43 30 02 00 00 C0 EB 5E 41 BB 44 20 01 AA 8B C1 8B F1 41 3B D3 41 BA 44 30 01 AA 74 0F 41 3B D2 75 11 B8 08 00 00 00 8D 70 FC EB 07 }
        $seq_2 = { 0F B7 84 39 58 07 00 00 66 42 89 04 19 48 83 C1 02 66 85 C0 75 EA 48 8D 15 99 02 00 00 49 8B CB }
    condition:
        int16(uint32(0x3C) + 0x5c) == 0x0001 and int16(uint32(0x3C) + 0x18) == 0x020b and $seq_1 and $seq_2
}