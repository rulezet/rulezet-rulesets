rule sig_20161024_af239f4f9097613dbe846f0af1aec0ee {
  meta:
    description = "datamaliciousorder - file 20161024_af239f4f9097613dbe846f0af1aec0ee.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "40ff1beeb21b92a8db35834fca4915cc1e826cfeae23e99a3ba0e68128711c2b"

  strings:
    $s1 = "} while (kh++ < mq);" fullword ascii

  condition:
    uint16(0) == 0x0a0a and
    all of them
}