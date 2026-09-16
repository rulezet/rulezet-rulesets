rule Trojan_Autorun_Trojan_GenericKDZ_94847_137_1 {
  meta:
    description = "datamaliciousorder - file Trojan.Autorun_Trojan.GenericKDZ.94847_137_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "b163fed93ae50d73ecdfa5f6769fb19cdc38f11431229a93059e7af66dd3e931"

  strings:
    $s1 = "q{authorized sources. Certain upgrades, support, and other services may be offered only to users of" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}