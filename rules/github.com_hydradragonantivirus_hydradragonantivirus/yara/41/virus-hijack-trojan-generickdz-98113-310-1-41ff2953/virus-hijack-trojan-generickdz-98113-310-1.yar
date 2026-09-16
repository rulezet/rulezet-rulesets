rule Virus_Hijack_Trojan_GenericKDZ_98113_310_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.98113_310_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "481d8adbe821915d13b7873bc00fc034c1f9a45763d02ac0ef2d7f615d1ab409"

  strings:
    $s1 = "G&COnn" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}