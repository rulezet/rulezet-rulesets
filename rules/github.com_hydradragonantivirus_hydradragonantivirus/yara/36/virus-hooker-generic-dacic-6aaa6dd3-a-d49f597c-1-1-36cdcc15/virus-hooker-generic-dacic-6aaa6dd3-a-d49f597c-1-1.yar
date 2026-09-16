rule Virus_Hooker_Generic_Dacic_6AAA6DD3_A_D49F597C_1_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hooker_Generic.Dacic.6AAA6DD3.A.D49F597C_1_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "040274c95d2cc2d5ed4031c1613e934f32b3c327f6a18bcfe6c646e31a217456"

  strings:
    $s1 = "sHoU)A" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}