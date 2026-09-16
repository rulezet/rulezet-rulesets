rule VirusShareTrojanSiggen910927_1 {
  meta:
    description = "datamaliciousorder - file VirusShareTrojanSiggen910927_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "9115464c05c12c6ef4877fc7d77fdac135d2d809c0d59a48c34c16f18cdc0de2"

  strings:
    $s1 = "WhaR;8(_;" fullword ascii
    $s2 = "n@Yowt" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}