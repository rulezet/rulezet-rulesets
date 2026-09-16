rule sig_20161024_f82e28f892cfc15eb9a7ab6611da4829 {
  meta:
    description = "datamaliciousorder - file 20161024_f82e28f892cfc15eb9a7ab6611da4829.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "3022f79be7dba2c38a8914b959b1547618c3825e81da3bc2f2b8dcb8e0a90d11"

  strings:
    $s1 = "} while (wb++ < qf);" fullword ascii

  condition:
    uint16(0) == 0x0a0a and
    all of them
}