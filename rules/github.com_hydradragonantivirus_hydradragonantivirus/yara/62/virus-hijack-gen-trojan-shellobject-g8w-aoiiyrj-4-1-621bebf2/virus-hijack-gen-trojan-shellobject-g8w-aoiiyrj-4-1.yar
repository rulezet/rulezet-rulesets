rule Virus_Hijack_Gen_Trojan_ShellObject_g8W_aOIIYRj_4_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.g8W@aOIIYRj_4_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "d3f207892eeaa1d4969fdc17a0bf02c674eb7d6ba90d79dcae560344c4c877e8"

  strings:
    $s1 = "SELECT * From Win32_" fullword wide
    $s2 = "SELECT * From AntiVirusProduct" fullword wide

  condition:
    uint16(0) == 0x5a4d and
    all of them
}