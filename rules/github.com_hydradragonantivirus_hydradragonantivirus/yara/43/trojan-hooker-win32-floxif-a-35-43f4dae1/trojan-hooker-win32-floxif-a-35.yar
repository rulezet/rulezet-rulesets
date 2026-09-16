rule Trojan_Hooker_Win32_Floxif_A_35 {
  meta:
    description = "datamaliciousorder - file Trojan.Hooker_Win32.Floxif.A_35.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "1ee410fd365f22187748377c07df73f64984da4c5dbc7acd473b55a3cd655096"

  strings:
    $s1 = "bAWN?|Z0\\" fullword ascii
    $s2 = "bOLD>0w" fullword ascii
    $s3 = "6!rOte" fullword ascii
    $s4 = "m`yiTe&" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}