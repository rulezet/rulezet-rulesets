rule Virus_Hijack_Gen_Trojan_ShellObject_eyY_aOWVavp_14_2 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.eyY@aOWVavp_14_2.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "1eb1c2ed83491e1e96d413514945621c0c14745d93ce0791d2542794f3e5a25b"

  strings:
    $s1 = "?$SifT" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}