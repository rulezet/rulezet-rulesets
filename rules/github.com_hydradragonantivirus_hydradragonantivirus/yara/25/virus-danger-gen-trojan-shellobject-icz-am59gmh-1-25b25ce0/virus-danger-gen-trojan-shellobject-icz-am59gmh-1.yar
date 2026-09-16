rule Virus_Danger_Gen_Trojan_ShellObject_iCZ_am59Gmh_1 {
  meta:
    description = "datamaliciousorder - file Virus.Danger_Gen.Trojan.ShellObject.iCZ@am59Gmh_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "203844ccc0f54888825743b724e1b726b1fafa91309adaef039059bf9b473e7c"

  strings:
    $s1 = "sTUd$2" fullword ascii
    $s2 = "+#MILD" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}