rule Virus_Hijack_Gen_Trojan_ShellObject_f0W_aiqugi_20 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.f0W@aiqugi_20.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "3bec09696a7b6221fd21515b8457357f322580df90af2591b47b2ef06efae5ef"

  strings:
    $s1 = "N4. Language Packs and Proofing Tools. If you acq" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}