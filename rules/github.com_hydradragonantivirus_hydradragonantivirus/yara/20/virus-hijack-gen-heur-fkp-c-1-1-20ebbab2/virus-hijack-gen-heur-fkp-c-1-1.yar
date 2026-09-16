rule Virus_Hijack_Gen_Heur_FKP__c__1_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Heur.FKP.!c!.1_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "5fc48f24f17e033f0e57cfe09b31365c40c2a900892492c9a336f5b87ee063f1"

  strings:
    $s1 = "Outpitch" fullword wide
    $s2 = "Beatae" fullword wide
    $s3 = "*456*-@36*=.42+?Kamas" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}