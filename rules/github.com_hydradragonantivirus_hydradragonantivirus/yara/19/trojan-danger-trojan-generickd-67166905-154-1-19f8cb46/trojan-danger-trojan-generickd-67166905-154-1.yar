rule Trojan_Danger_Trojan_GenericKD_67166905_154_1 {
  meta:
    description = "datamaliciousorder - file Trojan.Danger_Trojan.GenericKD.67166905_154_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "a6ecd5c417a26808b986894df1f8f0d29c52638418657018730d07333990e459"

  strings:
    $s1 = "HUniversity Online Library (" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}