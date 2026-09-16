rule Macos_Infostealer_Banshee_5d6bfde9 {
    meta:
        author = "Elastic Security"
        id = "5d6bfde9-f5ac-4988-a8c9-f22954073a79"
        fingerprint = "70f926f87f57018d1cf2b5aac0b8e7975d0ddbe8c1aecbd58a49956e54a27b72"
        creation_date = "2024-09-13"
        last_modified = "2024-10-24"
        threat_name = "Macos.Infostealer.Banshee"
        reference_sample = "03ca50947875b4498013503cd4e26282ff764b8d7a1dc1d801d1d08595986cf8"
        severity = 100
        arch_context = "x86, arm64"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "macos"
    strings:
        $binary_0 = { 89 F0 31 D2 41 F7 F6 0F B6 04 11 41 30 04 37 48 8D 46 01 48 89 C2 4C 09 F2 48 C1 EA 20 }
        $str_0 = { 64 69 74 74 6F 20 2D 63 20 2D 6B 20 25 40 20 25 40 2E 7A 69 70 20 2D 2D 6E 6F 72 73 72 63 20 2D 2D 6E 6F 65 78 74 61 74 74 72 00 }
        $str_1 = "run_controller"
        $str_2 = "initWithEncryptionKey"
        $str_3 = "killall Terminal"
    condition:
        $binary_0 and all of ($str_*)
}