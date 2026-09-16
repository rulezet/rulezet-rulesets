rule Virus_Hijack_Trojan_GenericKDZ_105924_112_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.105924_112_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "0e25f878a4d574174bf1be0b46f17b942b4075cd8066ab5823ae0c127d762233"

  strings:
    $s1 = "Ogre*lq5" fullword ascii
    $s2 = "Kk&GoRB" fullword ascii
    $s3 = "?k!GuNA" fullword ascii
    $s4 = "O(SelL" fullword ascii
    $s5 = " OxaN>" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}