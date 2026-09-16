rule Trojan_Danger_Trojan_GenericKD_67166905_399_1 {
  meta:
    description = "datamaliciousorder - file Trojan.Danger_Trojan.GenericKD.67166905_399_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "bf33ab1312938a54a8f149b00e89b6c09877736a72ea9c096e135f2be38f7078"

  strings:
    $s1 = "Gape@*b/" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}