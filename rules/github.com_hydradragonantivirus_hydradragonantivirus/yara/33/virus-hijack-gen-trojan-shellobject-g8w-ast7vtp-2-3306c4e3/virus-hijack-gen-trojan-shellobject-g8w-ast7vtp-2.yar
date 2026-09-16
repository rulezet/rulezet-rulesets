rule Virus_Hijack_Gen_Trojan_ShellObject_g8W_aSt7VTp_2 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.g8W@aSt7VTp_2.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "0470726299a17eeb4ef19f687768771b4f6bc86bd75561442723c25564e48242"

  strings:
    $s1 = "2. Notice of Dispute. In the event of a dispute, you or Microsoft must give the oth`" fullword ascii
    $s2 = "9upurchase orders transmitted from Oracle Purchasing, during a 12 month period. You may not exceed the licensed number of" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}