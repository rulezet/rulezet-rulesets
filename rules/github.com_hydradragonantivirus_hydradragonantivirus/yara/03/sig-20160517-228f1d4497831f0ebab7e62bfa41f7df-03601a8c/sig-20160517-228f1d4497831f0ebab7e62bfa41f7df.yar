rule sig_20160517_228f1d4497831f0ebab7e62bfa41f7df {
  meta:
    description = "datamaliciousorder - file 20160517_228f1d4497831f0ebab7e62bfa41f7df.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "d162c5a6182c4bc28281c12ad5b2a25e857b3ba6c9f5ba087eac763be6bbc79b"

  strings:
    $s1 = "var y2g3='vcxgnmapzoivraz1rt egxyqjoy2fzhrbbggtund1brz4aimgizl1rcs12dz2xixtrvggw3q1msekt=ldxop\\'jopzotqfpimcr4ymxnzjenlibueeefe" ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}