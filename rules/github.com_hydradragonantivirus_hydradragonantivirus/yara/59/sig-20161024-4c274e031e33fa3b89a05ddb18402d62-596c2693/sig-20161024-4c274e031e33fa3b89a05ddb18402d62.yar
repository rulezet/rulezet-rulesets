rule sig_20161024_4c274e031e33fa3b89a05ddb18402d62 {
  meta:
    description = "datamaliciousorder - file 20161024_4c274e031e33fa3b89a05ddb18402d62.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "5f0bd12c1a8fae5cf3f0a1a4e56a3c4ff4581a95b7c9f77acbe9c7c7dafd2c0d"

  strings:
    $s1 = "} while (ok0++ < tn);" fullword ascii

  condition:
    uint16(0) == 0x0a0a and
    all of them
}