rule VirusShareTrojanSiggen1528003 {
  meta:
    description = "datamaliciousorder - file VirusShareTrojanSiggen1528003.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "ecba14f22692df756b5d1f26b5235e29abf91e9a5557ceb9a1bc83d09bc47cc4"

  strings:
    $s1 = "Copyright LimerBoy " fullword wide
    $s2 = "Rich@!" fullword ascii
    $s3 = "This _" fullword ascii
    $s4 = "F`GAPE" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}