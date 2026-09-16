rule Trojan_Danger_Trojan_GenericKD_67166905_357_1 {
  meta:
    description = "datamaliciousorder - file Trojan.Danger_Trojan.GenericKD.67166905_357_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "d55880847b86dcaf80381949a5f64e161eb8eebe879148797338815429262742"

  strings:
    $s1 = "pUjA)r" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}