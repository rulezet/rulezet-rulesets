rule Virus_Hijack_Gen_Variant_Zbot_40_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Variant.Zbot.40_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "f48adeb2b6b2c236f3a39965e0891c483c1f5b40d8d2584997e2cfcfda2a8726"

  strings:
    $s1 = "Monoammonium" fullword wide
    $s2 = "Gantsl" fullword wide

  condition:
    uint16(0) == 0x5a4d and
    all of them
}