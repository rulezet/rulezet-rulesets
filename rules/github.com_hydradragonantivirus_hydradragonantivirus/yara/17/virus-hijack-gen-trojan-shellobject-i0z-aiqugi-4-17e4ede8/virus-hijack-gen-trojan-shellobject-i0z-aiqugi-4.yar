rule Virus_Hijack_Gen_Trojan_ShellObject_i0Z_aiqugi_4 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.i0Z@aiqugi_4.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "4765401e5a8741501c19b310c6075a41a3735cff49aa7f16fc42023557d1c0c9"

  strings:
    $s1 = "o4. Language Packs and Proofing Tools. If you acq" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}