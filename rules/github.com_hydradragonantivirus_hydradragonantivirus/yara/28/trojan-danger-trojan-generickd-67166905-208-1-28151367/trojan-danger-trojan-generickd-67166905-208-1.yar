rule Trojan_Danger_Trojan_GenericKD_67166905_208_1 {
  meta:
    description = "datamaliciousorder - file Trojan.Danger_Trojan.GenericKD.67166905_208_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "6b96466b5accf1c00413d977422a3381ef01013574000bb467a4266301ca6d3d"

  strings:
    $s1 = "jUniversity Online Library (" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}