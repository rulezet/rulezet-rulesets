rule Virus_Hijack_Gen_Trojan_ShellObject_f0W_aiqugi_21 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.f0W@aiqugi_21.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "cb19be18aa9d11579a8b59a55ac2afe353859d9141dc88211ac647ff0aceecd6"

  strings:
    $s1 = "u/4. Language Packs and Proofing Tools. If you acq" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}