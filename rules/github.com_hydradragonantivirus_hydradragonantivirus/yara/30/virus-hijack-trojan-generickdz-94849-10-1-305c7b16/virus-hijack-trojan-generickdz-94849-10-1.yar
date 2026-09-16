rule Virus_Hijack_Trojan_GenericKDZ_94849_10_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.94849_10_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "f2d902c03163066d4da469d9a5043486f509158ea377374f51a9523232d20505"

  strings:
    $s1 = "tOLD#c" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}