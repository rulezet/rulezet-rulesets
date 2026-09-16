rule Virus_Hijack_Gen_Trojan_ShellObject_f0W_aiqugi_97 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.f0W@aiqugi_97.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "3b1acab04dcbd06fdcf7a3dcc160ad31f27bb5b87c919200bf0065e6b7bc7d86"

  strings:
    $s1 = " 54. Language Packs and Proofing Tools. If you acq" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}