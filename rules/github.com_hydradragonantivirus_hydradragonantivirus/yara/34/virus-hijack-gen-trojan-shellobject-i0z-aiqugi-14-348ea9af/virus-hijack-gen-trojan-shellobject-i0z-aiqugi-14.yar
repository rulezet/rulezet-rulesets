rule Virus_Hijack_Gen_Trojan_ShellObject_i0Z_aiqugi_14 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.i0Z@aiqugi_14.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "43d2fae9d34d21401906783e50f1f3151c22142cacfcecf45447d236ff724c24"

  strings:
    $s1 = "m4. Language Packs and Proofing Tools. If you acq" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}