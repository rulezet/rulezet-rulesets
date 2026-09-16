rule Virus_Hijack_Gen_Heur_FKP__c__1_3 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Heur.FKP.!c!.1_3.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "43addebcb4364a9c9707cb8956ae8ddf6953aa8cff5585296a101861bbf1602b"

  strings:
    $s1 = "bolimba" fullword wide
    $s2 = "Mummied" fullword wide
    $s3 = "Overmourn" fullword wide

  condition:
    uint16(0) == 0x5a4d and
    all of them
}