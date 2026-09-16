rule Virus_Hijack_Gen_Trojan_ShellObject_dyX_a0MYK1d_5_2 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.dyX@a0MYK1d_5_2.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "f6e2e53370a23c05d3281ab798df051354f54a75debb64d2025236b164164a24"

  strings:
    $s1 = "rOKa;[&" fullword ascii
    $s2 = "@Blaw$K" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}