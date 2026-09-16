rule sig_20161024_4ebb075f1548389aede2c1a9f830d1e4 {
  meta:
    description = "datamaliciousorder - file 20161024_4ebb075f1548389aede2c1a9f830d1e4.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "86d315a55ab9997c5936706d3fda367b43645c0fd76934e1893ae85d7695b6f8"

  strings:
    $s1 = "} while (tp++ < gu0);" fullword ascii

  condition:
    uint16(0) == 0x0a0a and
    all of them
}