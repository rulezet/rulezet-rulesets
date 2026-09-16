rule Virus_Hijack_Gen_Trojan_ShellObject_f0W_aiqugi_37 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.f0W@aiqugi_37.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "d2d3b1782a0d3e67abdf5d73b435c6c98c357c37aaafc0fe40b2a414de54f2c9"

  strings:
    $s1 = "~4. Language Packs and Proofing Tools. If you acq" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}