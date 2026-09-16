rule VirusShareBATSiggen250_127_1 {
  meta:
    description = "datamaliciousorder - file VirusShareBATSiggen250_127_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "e100adfefb4565c5cc84c936b4f50fa82b850b381945e16b1bfb3e25635a542d"

  strings:
    $s1 = "hello world " fullword wide
    $s2 = "test for you" fullword wide

  condition:
    uint16(0) == 0x5a4d and
    all of them
}