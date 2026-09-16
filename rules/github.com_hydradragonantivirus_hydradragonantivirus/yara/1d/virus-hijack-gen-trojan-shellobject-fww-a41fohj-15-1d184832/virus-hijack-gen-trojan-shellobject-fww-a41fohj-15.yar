rule Virus_Hijack_Gen_Trojan_ShellObject_fWW_a41FOHj_15 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.fWW@a41FOHj_15.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "3d20717da8c6cd5983bd9a551d197f5d856a35f007192f89227fda89d39aa905"

  strings:
    $s1 = "4(including the denial or cancellation of any export or other license); other event outside the reasonable control of the obliga" ascii
    $s2 = "4(including the denial or cancellation of any export or other license); other event outside the reasonable control of the obliga" ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}