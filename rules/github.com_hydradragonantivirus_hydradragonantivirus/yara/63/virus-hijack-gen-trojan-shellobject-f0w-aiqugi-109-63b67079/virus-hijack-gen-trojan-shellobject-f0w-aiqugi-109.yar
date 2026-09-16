rule Virus_Hijack_Gen_Trojan_ShellObject_f0W_aiqugi_109 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.f0W@aiqugi_109.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "2f93fa13c0d3a225c411be6395746e6702474882a08289c7891228a594de8306"

  strings:
    $s1 = "S4. Language Packs and Proofing Tools. If you acq" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}