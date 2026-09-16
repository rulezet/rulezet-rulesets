rule Virus_Hijack_Gen_Trojan_ShellObject_j8Z_ai6MB5n_2 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.j8Z@ai6MB5n_2.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "2508eba1861c183820159f226a19c9fbe3a4a8aeae4c386cd79fa00253b7a258"

  strings:
    $s1 = "wAmerica, call (800) MICROSOFT or see microsoft.com/info/nareturns.htm." fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}