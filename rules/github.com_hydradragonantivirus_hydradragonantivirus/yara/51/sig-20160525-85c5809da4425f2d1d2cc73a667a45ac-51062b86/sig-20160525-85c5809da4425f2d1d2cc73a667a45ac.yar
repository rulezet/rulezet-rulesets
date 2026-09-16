rule sig_20160525_85c5809da4425f2d1d2cc73a667a45ac {
  meta:
    description = "datamaliciousorder - file 20160525_85c5809da4425f2d1d2cc73a667a45ac.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "f55ef2915314a1b30f9c2575a175ca6e2f53dd1fee7715f3d7346f56909ce79b"

  strings:
    $s1 = "suidarelcitrapc rav\\n;\"b76x\\\\f2x\\\\\" = gedotdarc rav\\n;\"383x\\\\n5\" = ecapsetihwxelfc rav\\n;\"03x\\\\\" = modnarc rav" ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}