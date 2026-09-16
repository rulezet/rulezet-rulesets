rule Trojan_Danger_Trojan_GenericKD_67269844_52 {
  meta:
    description = "datamaliciousorder - file Trojan.Danger_Trojan.GenericKD.67269844_52.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "ec3f4476a6522ebaf58bd47e9e5498a11dc04053bc5597adbbc127c1983b8299"

  strings:
    $s1 = "Compile Script to .exe (x64).lnk" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}