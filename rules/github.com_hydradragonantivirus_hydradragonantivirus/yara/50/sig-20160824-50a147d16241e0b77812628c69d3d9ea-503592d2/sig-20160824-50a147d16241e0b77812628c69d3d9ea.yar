rule sig_20160824_50a147d16241e0b77812628c69d3d9ea {
  meta:
    description = "datamaliciousorder - file 20160824_50a147d16241e0b77812628c69d3d9ea.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "6d9969e885c5bf1f1306a66b95bbf7e1701cb8a427097552b77d381510a6268d"

  strings:
    $s1 = "var DOh = new Array(\"\\x66\",\"\\x75\",\"\\x6e\",\"\\x63\",\"\\x74\",\"\\x69\",\"\\x6f\",\"\\x20\",\"\\x6b\",\"\\x28\",\"\\x29" ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}