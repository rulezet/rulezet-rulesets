rule VirusShareTrojanDownLoader2255152 {
  meta:
    description = "datamaliciousorder - file VirusShareTrojanDownLoader2255152.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "75c9bafcf1871bfe7ac4351f62fb1d8af422675caa714342cce1118cfc761022"

  strings:
    $s1 = "c:\\users\\user\\documents\\visual studio 2012\\Projects\\WindowsApplication2\\WindowsApplication2\\obj\\Debug\\WindowsApplicati" ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}