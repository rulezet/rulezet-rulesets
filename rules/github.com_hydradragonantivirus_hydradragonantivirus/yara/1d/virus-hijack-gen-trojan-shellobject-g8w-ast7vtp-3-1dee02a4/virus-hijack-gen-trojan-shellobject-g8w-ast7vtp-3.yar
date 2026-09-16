rule Virus_Hijack_Gen_Trojan_ShellObject_g8W_aSt7VTp_3 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.g8W@aSt7VTp_3.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "e951c8c9f2dfd3135b6be7d6bf8fdfe26f55705dc50cecc2d8e8d0771635821e"

  strings:
    $s1 = "2. Notice of Dispute. In the event of a dispute, you or Microsoft must give the oth`" fullword ascii
    $s2 = "Tpurchase orders transmitted from Oracle Purchasing, during a 12 month period. You may not exceed the licensed number of" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}