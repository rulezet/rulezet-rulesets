rule VirusShareTrojanInject36111_45_1 {
  meta:
    description = "datamaliciousorder - file VirusShareTrojanInject36111_45_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "f4a3ac2bbe834949e1b50acab2af104e0c428035554cb96b2578b273f10129ce"

  strings:
    $s1 = "REnK&s" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}