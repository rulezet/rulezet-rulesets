rule Virus_Autorun_Worm_FakeDoc_2_1 {
  meta:
    description = "datamaliciousorder - file Virus.Autorun_Worm.FakeDoc_2_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "5556636aff30e628d124a5af65dd598836b78c33f704a1dfe389dbc6cb91ba6e"

  strings:
    $s1 = "Microsoft Office Diagnostics.lnk" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}