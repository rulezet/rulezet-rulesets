rule Virus_Hijack_Gen_Trojan_ShellObject_D8Z_aeuJE7m_6_2 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.D8Z@aeuJE7m_6_2.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "7db665450d8b0e58a4636ab86c4051baa89b38d36018cdfe2f6a9eec5466ff80"

  strings:
    $s1 = "(NASi'" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}