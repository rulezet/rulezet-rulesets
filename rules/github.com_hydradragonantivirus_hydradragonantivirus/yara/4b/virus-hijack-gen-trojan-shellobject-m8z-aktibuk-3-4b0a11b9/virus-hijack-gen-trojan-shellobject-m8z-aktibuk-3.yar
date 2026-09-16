rule Virus_Hijack_Gen_Trojan_ShellObject_m8Z_aKTibuk_3 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.m8Z@aKTibuk_3.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "de96c48090a421e6bd484ce18c631511377e388b660ea1780719f68d32bfa80e"

  strings:
    $s1 = "~*TEAK" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}