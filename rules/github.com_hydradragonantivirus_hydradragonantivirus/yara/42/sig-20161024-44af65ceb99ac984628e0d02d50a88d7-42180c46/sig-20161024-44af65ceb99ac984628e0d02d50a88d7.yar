rule sig_20161024_44af65ceb99ac984628e0d02d50a88d7 {
  meta:
    description = "datamaliciousorder - file 20161024_44af65ceb99ac984628e0d02d50a88d7.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "272d6c844ec6fee3dfaa84060a61e7a13eb5445754d8ced0544768634b2ac9a9"

  strings:
    $s1 = "} while (lw++ < bc);" fullword ascii

  condition:
    uint16(0) == 0x0a0a and
    all of them
}