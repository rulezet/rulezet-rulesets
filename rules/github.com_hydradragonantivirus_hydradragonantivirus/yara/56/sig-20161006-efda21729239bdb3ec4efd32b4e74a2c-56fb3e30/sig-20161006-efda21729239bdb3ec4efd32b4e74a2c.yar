rule sig_20161006_efda21729239bdb3ec4efd32b4e74a2c {
  meta:
    description = "datamaliciousorder - file 20161006_efda21729239bdb3ec4efd32b4e74a2c.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "aaa48e2b98cf76ecef9365ec26b2e36d2c9de92274daa42d4eda15ae23e481d5"

  strings:
    $s1 = "} while (dl++ < ow);" fullword ascii

  condition:
    uint16(0) == 0x2f0a and
    all of them
}