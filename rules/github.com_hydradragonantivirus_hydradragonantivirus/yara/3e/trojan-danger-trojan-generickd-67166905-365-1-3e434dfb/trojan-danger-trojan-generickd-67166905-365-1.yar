rule Trojan_Danger_Trojan_GenericKD_67166905_365_1 {
  meta:
    description = "datamaliciousorder - file Trojan.Danger_Trojan.GenericKD.67166905_365_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "55d37b15a24e41f8c4d3cb7a0148d2f3fdce09ef5c3d79e61811781d962aa6ae"

  strings:
    $s1 = "2virtualization, see the Additional Terms." fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}