rule Virus_Hijack_Gen_Trojan_ShellObject_g8W_aSt7VTp {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.g8W@aSt7VTp.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "81432bc3470ce69bc3f5902de5775d00051c07f0853c0d0be1324965f463ee72"

  strings:
    $s1 = "2. Notice of Dispute. In the event of a dispute, you or Microsoft must give the oth`" fullword ascii
    $s2 = "Jpurchase orders transmitted from Oracle Purchasing, during a 12 month period. You may not exceed the licensed number of" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}