rule Virus_Hijack_Gen_Trojan_ShellObject_i0Z_aiqugi_22 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.i0Z@aiqugi_22.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "4883ad3143b63a4ada209091e84c578a62c6a2ae042e7ffc8e19fdb3948abd2c"

  strings:
    $s1 = "s4. Language Packs and Proofing Tools. If you acq" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}