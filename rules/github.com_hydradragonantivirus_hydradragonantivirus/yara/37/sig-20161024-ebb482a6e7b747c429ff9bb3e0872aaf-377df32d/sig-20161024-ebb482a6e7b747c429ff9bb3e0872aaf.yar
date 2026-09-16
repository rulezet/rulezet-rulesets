rule sig_20161024_ebb482a6e7b747c429ff9bb3e0872aaf {
  meta:
    description = "datamaliciousorder - file 20161024_ebb482a6e7b747c429ff9bb3e0872aaf.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "f0c4b23f7ec0785adf8371269b2e64f6922623a3a9cde1f006aa8a0aaf4b53fd"

  strings:
    $s1 = "} while (my++ < rt);" fullword ascii

  condition:
    uint16(0) == 0x0a0a and
    all of them
}