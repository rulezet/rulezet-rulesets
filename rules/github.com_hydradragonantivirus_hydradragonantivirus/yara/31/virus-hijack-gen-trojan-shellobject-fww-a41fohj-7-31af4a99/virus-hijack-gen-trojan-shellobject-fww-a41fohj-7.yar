rule Virus_Hijack_Gen_Trojan_ShellObject_fWW_a41FOHj_7 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.fWW@a41FOHj_7.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "bed35fa23850a1923b26a82ea9967cdb65c28b1fccfa7ddcb5cd475706956c5c"

  strings:
    $s1 = " (including the denial or cancellation of any export or other license); other event outside the reasonable control of the obliga" ascii
    $s2 = " (including the denial or cancellation of any export or other license); other event outside the reasonable control of the obliga" ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}