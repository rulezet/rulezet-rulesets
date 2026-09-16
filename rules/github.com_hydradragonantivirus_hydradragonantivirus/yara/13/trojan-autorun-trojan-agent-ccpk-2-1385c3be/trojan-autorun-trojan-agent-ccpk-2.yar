rule Trojan_Autorun_Trojan_Agent_CCPK_2 {
  meta:
    description = "datamaliciousorder - file Trojan.Autorun_Trojan.Agent.CCPK_2.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "f7fb1c23d40ce0e6cc75db49b546f209181b55c19fe564c258d8403b2a2b3529"

  strings:
    $s1 = "Windows Moviess Maker Network Sharing ServiceEha" fullword ascii
    $s2 = "Physical devicessasd to share Windows Movie Maker NetworkLwq Library." fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}