rule sig_20161024_9fe39beede54bcaf4faa92ebf95241be {
  meta:
    description = "datamaliciousorder - file 20161024_9fe39beede54bcaf4faa92ebf95241be.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "90138e740ca0d2fb3ee622133c3e9c2513a18b3a5bff53c48b03c9b6909fa74e"

  strings:
    $s1 = "} while (if0++ < iu);" fullword ascii

  condition:
    uint16(0) == 0x0a0a and
    all of them
}