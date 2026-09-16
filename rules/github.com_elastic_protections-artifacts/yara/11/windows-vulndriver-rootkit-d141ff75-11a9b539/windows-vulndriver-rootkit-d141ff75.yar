rule Windows_VulnDriver_Rootkit_d141ff75 {
    meta:
        author = "Elastic Security"
        id = "d141ff75-6ffe-4cae-b839-cdbbfe74bfe4"
        fingerprint = "283e528a24c138af82ea527a8dd8c132aa2ef340d84e316adb482b224297cd30"
        creation_date = "2026-05-22"
        last_modified = "2026-07-29"
        description = "Subject: WDKTestCert zezec,132961360795713868"
        threat_name = "Windows.VulnDriver.Rootkit"
        reference_sample = "23e89fd30a1c7db37f3ea81b779ce9acf8a4294397cbb54cff350d54afcfd931"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $subject_name = { 06 03 55 04 03 [2] 57 44 4B 54 65 73 74 43 65 72 74 20 7A 65 7A 65 63 2C 31 33 32 39 36 31 33 36 30 37 39 35 37 31 33 38 36 38 }
        $str1 = "Malicious.pdb"
    condition:
        int16(uint32(0x3C) + 0x5c) == 0x0001 and int16(uint32(0x3C) + 0x18) == 0x020b and $subject_name and $str1
}