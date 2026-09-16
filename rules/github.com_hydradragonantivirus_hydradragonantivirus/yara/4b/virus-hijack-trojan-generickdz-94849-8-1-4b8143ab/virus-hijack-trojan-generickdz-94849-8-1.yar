rule Virus_Hijack_Trojan_GenericKDZ_94849_8_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.94849_8_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "a9b8be4eb677ad5d628582f92e01c5ee3d1a1fd1829f1a7592c12769f00486d3"

  strings:
    $s1 = "nEed$-" fullword ascii
    $s2 = "h#sOap" fullword ascii
    $s3 = "\"]RoWy." fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}