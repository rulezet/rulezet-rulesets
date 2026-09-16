rule Virus_Hijack_Gen_Trojan_ShellObject_j8Z_ai6MB5n_9 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.j8Z@ai6MB5n_9.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "ac554ec6ca22a3fdd19f9dc7196650762ecb103c8137a1e48c8639961d7e54cd"

  strings:
    $s1 = "Rich*/" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}