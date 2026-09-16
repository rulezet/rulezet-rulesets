rule Virus_Hijack_Gen_Trojan_ShellObject_f0W_aiqugi_71 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.f0W@aiqugi_71.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "223bf7bb3d840ae5bedf88f214e277f865d96a662f07b79a3fa6630d30fcef46"

  strings:
    $s1 = "]4. Language Packs and Proofing Tools. If you acq" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}