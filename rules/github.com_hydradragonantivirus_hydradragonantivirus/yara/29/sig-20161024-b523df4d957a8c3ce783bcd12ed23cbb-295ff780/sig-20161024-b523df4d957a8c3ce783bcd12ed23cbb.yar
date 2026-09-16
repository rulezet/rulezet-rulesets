rule sig_20161024_b523df4d957a8c3ce783bcd12ed23cbb {
  meta:
    description = "datamaliciousorder - file 20161024_b523df4d957a8c3ce783bcd12ed23cbb.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "155180872a3a7ee8e3d3dca4f1949afa6a8d3a9192f679495f09b17fc2875a6c"

  strings:
    $s1 = "} while (yt++ < fq);" fullword ascii

  condition:
    uint16(0) == 0x0a0a and
    all of them
}