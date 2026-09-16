rule VirusShareTrojanPWSPanda2401_1 {
  meta:
    description = "datamaliciousorder - file VirusShareTrojanPWSPanda2401_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "f3507f3764076c4e6e75ebab425bc0d54b613eb3ea49231b61dceec391adf98b"

  strings:
    $s1 = "Nontechnological http://www.Maimon.com" fullword wide
    $s2 = "CyberLink Corporation" fullword wide

  condition:
    uint16(0) == 0x5a4d and
    all of them
}