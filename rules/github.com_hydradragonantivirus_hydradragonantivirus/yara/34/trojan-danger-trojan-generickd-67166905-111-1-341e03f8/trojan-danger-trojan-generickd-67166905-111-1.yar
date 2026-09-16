rule Trojan_Danger_Trojan_GenericKD_67166905_111_1 {
  meta:
    description = "datamaliciousorder - file Trojan.Danger_Trojan.GenericKD.67166905_111_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "7dbe971657a2808522cc7dbba1210922a4d9b618069b5d11fdbbed5586467ff2"

  strings:
    $s1 = "$Favailable at go.microsoft.com/fwlink/?linkid=245497 to the AAA. You agree to commence arbitration only" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}