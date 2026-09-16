rule Trojan_Autorun_Trojan_GenericKDZ_94659_2 {
  meta:
    description = "datamaliciousorder - file Trojan.Autorun_Trojan.GenericKDZ.94659_2.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "e458fffbfab7df940b0fc844a5905209f8911247fcde2b6f0098d079a13749bf"

  strings:
    $s1 = "mdd4g<:hill<oDBpqttDwLJxy||L" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}