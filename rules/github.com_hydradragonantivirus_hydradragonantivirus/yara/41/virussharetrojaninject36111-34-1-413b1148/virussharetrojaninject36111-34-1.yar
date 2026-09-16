rule VirusShareTrojanInject36111_34_1 {
  meta:
    description = "datamaliciousorder - file VirusShareTrojanInject36111_34_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "c18a4872c385663b087a4b0ce9eb658c6c9de484a60e87c4b9967502161e228c"

  strings:
    $s1 = "o(NAIo" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}