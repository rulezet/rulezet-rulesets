rule Trojan_Hooker_Win32_Floxif_A_43 {
  meta:
    description = "datamaliciousorder - file Trojan.Hooker_Win32.Floxif.A_43.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "80be94f6d76fb981e4fd583c1a048951fac83f450d8a404cfeb17d8298c17a49"

  strings:
    $s1 = "BIT COMPUTER CO., LTD.0" fullword ascii
    $s2 = "BIT COMPUTER CO., LTD.1" fullword ascii
    $s3 = "Action@QA" fullword ascii
    $s4 = "Management Team10" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}