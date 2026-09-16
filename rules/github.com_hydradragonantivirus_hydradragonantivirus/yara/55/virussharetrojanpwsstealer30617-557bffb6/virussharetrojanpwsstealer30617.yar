rule VirusShareTrojanPWSStealer30617 {
  meta:
    description = "datamaliciousorder - file VirusShareTrojanPWSStealer30617.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "0fc40808f72336153c9e35e652482a1e10bc315e825bd69a4b5fee87ebe0b154"

  strings:
    $s1 = "Agent FSB" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}