rule Virus_Hijack_Gen_Heur_FKP__c__1_4 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Heur.FKP.!c!.1_4.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "3ef2714b8c612ebcd155ec7b6a64099ae814481dccfa93a5748640491dcf370b"

  strings:
    $s1 = "mendable" fullword wide
    $s2 = "Subabdominal" fullword wide

  condition:
    uint16(0) == 0x5a4d and
    all of them
}