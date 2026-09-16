rule Virus_Hooker__Generic_Dacic_6AAA6DD3_A_E33A450A_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hooker _Generic.Dacic.6AAA6DD3.A.E33A450A_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "3b50f15c68a61e98317e71066b7530eb00c44b0241dbc741899f473c946a6d6b"

  strings:
    $s1 = "D[rOud" fullword ascii
    $s2 = "!%vIgA" fullword ascii
    $s3 = "]@bAFt" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}