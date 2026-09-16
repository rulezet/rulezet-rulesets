rule Trojan_Danger_Trojan_GenericKD_72853156_177_1 {
  meta:
    description = "datamaliciousorder - file Trojan.Danger_Trojan.GenericKD.72853156_177_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "cc44e1882127bc1e2306d43783de2340a213022e970ce7de367c1f448e278d70"

  strings:
    $s1 = "(char)('d_X" fullword ascii
    $s2 = "nknown exception}" fullword ascii
    $s3 = "?length" fullword ascii
    $s4 = "Te Path" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}