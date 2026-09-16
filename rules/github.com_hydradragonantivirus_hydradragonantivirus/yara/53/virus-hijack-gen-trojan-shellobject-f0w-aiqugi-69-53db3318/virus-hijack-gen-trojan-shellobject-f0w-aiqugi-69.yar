rule Virus_Hijack_Gen_Trojan_ShellObject_f0W_aiqugi_69 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.f0W@aiqugi_69.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "19b91a59ea8b6aa6ba25780f9d9d0bda8ad4cae410c9d3fe5e029af33c51a199"

  strings:
    $s1 = "o4. Language Packs and Proofing Tools. If you acq" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}