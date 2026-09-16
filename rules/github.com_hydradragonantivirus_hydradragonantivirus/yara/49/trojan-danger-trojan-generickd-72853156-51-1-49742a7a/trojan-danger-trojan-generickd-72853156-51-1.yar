rule Trojan_Danger_Trojan_GenericKD_72853156_51_1 {
  meta:
    description = "datamaliciousorder - file Trojan.Danger_Trojan.GenericKD.72853156_51_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "ca634247edaa01fb72aea8a42470ccc93b3fd88324ff27ef11617460a996f310"

  strings:
    $s1 = "^OLE initialization b nbm  gh ailed.  Make sure that the OLE libraries are the correct version." fullword wide

  condition:
    uint16(0) == 0x5a4d and
    all of them
}