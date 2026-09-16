rule Virus_Hijack_Gen_Trojan_ShellObject_e8W_aycAujk_8_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.e8W@aycAujk_8_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "7a89d7167264d77656b8cac1cef82a3e16f3dd51d679b178833a953a5cb11235"

  strings:
    $s1 = "<Module>{C1BEE1C4-01DD-45E6-B4CD-883B5F952993}" fullword ascii
    $s2 = "d(ilOT" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}