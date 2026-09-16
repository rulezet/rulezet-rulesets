rule VirusShareTrojanInject36111_20_1 {
  meta:
    description = "datamaliciousorder - file VirusShareTrojanInject36111_20_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "d0fccd95bbf3d13aecf0301ba981395f585da51804145b73485bdabaa71159bf"

  strings:
    $s1 = "2s}Eu60}Gold?]j#" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}