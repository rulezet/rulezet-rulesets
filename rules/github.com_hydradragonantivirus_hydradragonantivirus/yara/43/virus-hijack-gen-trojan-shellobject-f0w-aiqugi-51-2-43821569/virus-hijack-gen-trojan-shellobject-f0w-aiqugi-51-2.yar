rule Virus_Hijack_Gen_Trojan_ShellObject_f0W_aiqugi_51_2 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.f0W@aiqugi_51_2.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "c3125bbbc460d3df6e6125e3acb29e34c0ae2447cf79b2a671b7da9ca710d18a"

  strings:
    $s1 = "8[mALO:}OH" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}