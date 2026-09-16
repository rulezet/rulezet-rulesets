rule Virus_Hijack_Gen_Trojan_ShellObject_m0Z_aiqugi_3 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.m0Z@aiqugi_3.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "b119e6f3d93b8d99b05271f018195a40daf873285a3c3ecbe3fdd8ccbffa6000"

  strings:
    $s1 = "hn4. Language Packs and Proofing Tools. If you acq" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}