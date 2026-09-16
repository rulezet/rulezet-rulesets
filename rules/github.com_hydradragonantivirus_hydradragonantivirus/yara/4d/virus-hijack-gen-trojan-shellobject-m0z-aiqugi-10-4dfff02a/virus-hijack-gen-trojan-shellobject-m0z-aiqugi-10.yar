rule Virus_Hijack_Gen_Trojan_ShellObject_m0Z_aiqugi_10 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.m0Z@aiqugi_10.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "fe94fc7beea3560cff09ee4ea68848d1b75a3b20039243d3a0c7a3b35b27077f"

  strings:
    $s1 = "E4. Language Packs and Proofing Tools. If you acq" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}