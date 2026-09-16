rule Virus_Hijack_Trojan_GenericKDZ_74550_376 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.74550_376.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "d6776b2d4212d565541c43f932e2893d6095dfbd4707474c91ccacbb4bbaaafd"

  strings:
    $s1 = "HoeR}1" fullword ascii
    $s2 = "HoeR}%" fullword ascii
    $s3 = "HoeR}U" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}