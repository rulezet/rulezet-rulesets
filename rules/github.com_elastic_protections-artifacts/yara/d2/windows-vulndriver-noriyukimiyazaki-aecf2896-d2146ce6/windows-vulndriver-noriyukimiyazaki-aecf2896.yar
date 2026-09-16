rule Windows_VulnDriver_NoriyukiMIYAZAKI_aecf2896 {
    meta:
        author = "Elastic Security"
        id = "aecf2896-a16c-4313-82d1-b8ab4b605ca7"
        fingerprint = "1f582ece12814dc6965e34af7704d5832e7468981d352915055d1708a62b35a4"
        creation_date = "2026-05-22"
        last_modified = "2026-07-20"
        description = "Subject: Noriyuki MIYAZAKI"
        threat_name = "Windows.VulnDriver.NoriyukiMIYAZAKI"
        reference_sample = "4fea15aabc4fc63a3e991412caf17283bbd257172ef7e255f40f5e22e0286902"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $subject_name = { 06 03 55 04 03 [2] 4E 6F 72 69 79 75 6B 69 20 4D 49 59 41 5A 41 4B 49 }
        $str1 = "SysInfo.pdb"
    condition:
        int16(uint32(0x3C) + 0x5c) == 0x0001 and $subject_name and $str1
}