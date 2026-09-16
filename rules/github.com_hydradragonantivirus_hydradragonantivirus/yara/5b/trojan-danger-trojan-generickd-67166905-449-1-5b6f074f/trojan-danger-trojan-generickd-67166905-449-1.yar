rule Trojan_Danger_Trojan_GenericKD_67166905_449_1 {
  meta:
    description = "datamaliciousorder - file Trojan.Danger_Trojan.GenericKD.67166905_449_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "a688a904c43842a83e1940960a6065e43f1bb721ba057e343a335e1cd0055d01"

  strings:
    $s1 = "PFUniversity Online Library (" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}