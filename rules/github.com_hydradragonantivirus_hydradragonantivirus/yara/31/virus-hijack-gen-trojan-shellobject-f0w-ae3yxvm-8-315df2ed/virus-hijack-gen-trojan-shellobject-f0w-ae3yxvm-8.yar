rule Virus_Hijack_Gen_Trojan_ShellObject_f0W_ae3yXvm_8 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.f0W@ae3yXvm_8.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "57976588d99503d62a23b7080c78ca24ee494826d20e3f5d5f400b476361e7dc"

  strings:
    $s1 = "X4. Language Packs and Proofing Tools. If you acq" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}