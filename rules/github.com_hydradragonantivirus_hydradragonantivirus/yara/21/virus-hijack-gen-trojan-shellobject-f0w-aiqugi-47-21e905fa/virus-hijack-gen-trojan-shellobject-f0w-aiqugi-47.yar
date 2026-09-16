rule Virus_Hijack_Gen_Trojan_ShellObject_f0W_aiqugi_47 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.f0W@aiqugi_47.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "33e061b62ecc4de51fa9b753d09e71b9d95de9918818f09fdddf3120d5f55782"

  strings:
    $s1 = "&4. Language Packs and Proofing Tools. If you acq" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}