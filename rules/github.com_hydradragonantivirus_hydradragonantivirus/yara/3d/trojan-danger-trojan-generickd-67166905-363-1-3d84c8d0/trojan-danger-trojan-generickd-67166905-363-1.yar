rule Trojan_Danger_Trojan_GenericKD_67166905_363_1 {
  meta:
    description = "datamaliciousorder - file Trojan.Danger_Trojan.GenericKD.67166905_363_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "539a93238c107526ca0a4979a66dba9c81c80cfe651e835af45f1521b90d7f06"

  strings:
    $s1 = "|available at go.microsoft.com/fwlink/?linkid=245497 to the AAA. You agree to commence arbitration only" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}