rule Virus_Hijack_Dropped_Backdoor_Padodor_BJ_656_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Dropped.Backdoor.Padodor.BJ_656_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "5c97f5877152b45d2a6f25b6d50a8d5153c7388e7345589ae626f59279a220b1"

  strings:
    $s1 = "slIm]lZ" fullword ascii
    $s2 = "D`LERP" fullword ascii
    $s3 = "BAck]~" fullword ascii
    $s4 = "SnUG#K" fullword ascii
    $s5 = "alBe{%" fullword ascii
    $s6 = "saMh`F" fullword ascii
    $s7 = "?FROM*" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}