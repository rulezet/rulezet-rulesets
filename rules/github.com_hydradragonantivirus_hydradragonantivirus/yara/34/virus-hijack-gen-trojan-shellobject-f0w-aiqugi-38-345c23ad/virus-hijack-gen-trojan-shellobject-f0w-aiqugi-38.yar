rule Virus_Hijack_Gen_Trojan_ShellObject_f0W_aiqugi_38 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.f0W@aiqugi_38.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "8a49f1a5ec9e6d0b567067e1e81c7fd7805827dc3c4dd8703a2f50b3ca48a83f"

  strings:
    $s1 = "9>4. Language Packs and Proofing Tools. If you acq" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}