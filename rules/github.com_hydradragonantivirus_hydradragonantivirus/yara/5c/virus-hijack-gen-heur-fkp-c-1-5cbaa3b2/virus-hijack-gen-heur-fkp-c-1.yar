rule Virus_Hijack_Gen_Heur_FKP__c__1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Heur.FKP.!c!.1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "c013617867fcb2583c1a11e3f59bff0bce5f00b599dec2158ae33312046ec83b"

  strings:
    $s1 = "bolimba" fullword wide
    $s2 = "Mummied" fullword wide
    $s3 = "Overmourn" fullword wide

  condition:
    uint16(0) == 0x5a4d and
    all of them
}