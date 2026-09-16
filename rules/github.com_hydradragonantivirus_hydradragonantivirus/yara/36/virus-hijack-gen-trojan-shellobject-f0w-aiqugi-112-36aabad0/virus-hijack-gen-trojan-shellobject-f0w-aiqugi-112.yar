rule Virus_Hijack_Gen_Trojan_ShellObject_f0W_aiqugi_112 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.f0W@aiqugi_112.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "1a0f006d83939890a7fd0933ea5791311999ff59daa45ce202c287358dff2278"

  strings:
    $s1 = "H4. Language Packs and Proofing Tools. If you acq" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}