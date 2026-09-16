rule Virus_Hijack_Trojan_GenericKDZ_98113_415_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.98113_415_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "222517cf7f31b7343238f2141d13c207f5a2b0799dc0d4da73d852fda3877ced"

  strings:
    $s1 = "+,PoMe&" fullword ascii
    $s2 = "@MabI&" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}