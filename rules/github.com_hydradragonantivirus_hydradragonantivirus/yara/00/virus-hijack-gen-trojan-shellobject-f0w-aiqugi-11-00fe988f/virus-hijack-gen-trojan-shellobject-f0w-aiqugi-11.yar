rule Virus_Hijack_Gen_Trojan_ShellObject_f0W_aiqugi_11 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.f0W@aiqugi_11.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "d7eddf68e3481eeb9305bfda1dc4fd4cf95c2ca3f3cb1dfeef461cb659512c4e"

  strings:
    $s1 = "24. Language Packs and Proofing Tools. If you acq" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}