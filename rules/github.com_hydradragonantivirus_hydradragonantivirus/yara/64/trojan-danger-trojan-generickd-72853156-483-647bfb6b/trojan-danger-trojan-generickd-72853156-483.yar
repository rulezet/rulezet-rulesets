rule Trojan_Danger_Trojan_GenericKD_72853156_483 {
  meta:
    description = "datamaliciousorder - file Trojan.Danger_Trojan.GenericKD.72853156_483.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "e365f3376687252bf716b35b9ebf1c70037b86d3fb886562a97ae72c9aca7d15"

  strings:
    $s1 = "Compile Script to .exe (x64).lnk" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}