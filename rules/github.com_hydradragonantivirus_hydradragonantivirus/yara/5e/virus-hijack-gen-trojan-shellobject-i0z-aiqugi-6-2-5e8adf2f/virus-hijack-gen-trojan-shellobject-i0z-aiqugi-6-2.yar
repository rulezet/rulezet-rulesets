rule Virus_Hijack_Gen_Trojan_ShellObject_i0Z_aiqugi_6_2 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.i0Z@aiqugi_6_2.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "ace32914388750b2de36f8c49d4d2928adfa07b0d06cdf9e30418cb3f5459c39"

  strings:
    $s1 = "bean ]4" fullword ascii
    $s2 = "b]anbA" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}