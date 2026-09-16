rule Virus_Hijack_Gen_Trojan_ShellObject_g8W_a4IOpRm {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.g8W@a4IOpRm.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "d7bb3c0514e025a23b890c03e5cf87c6f53174eb9d2d2e297d1e8fc442853cb9"

  strings:
    $s1 = "and you and Oracle agree to submit to the exc`" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}