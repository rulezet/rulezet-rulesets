rule Virus_Hijack_Gen_Trojan_ShellObject_i0Z_aiqugi_13 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.i0Z@aiqugi_13.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "6f986ee605931d2b4ed7f0416cd7cb10fa4e9b3e410d3f61ed4b66d0967168fa"

  strings:
    $s1 = ":4. Language Packs and Proofing Tools. If you acq" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}