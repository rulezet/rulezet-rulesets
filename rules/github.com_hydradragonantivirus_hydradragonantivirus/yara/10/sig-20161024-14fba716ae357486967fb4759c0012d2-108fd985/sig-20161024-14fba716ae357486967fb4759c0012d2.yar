rule sig_20161024_14fba716ae357486967fb4759c0012d2 {
  meta:
    description = "datamaliciousorder - file 20161024_14fba716ae357486967fb4759c0012d2.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "eac41651562a73924ff85c2732c1552e430d3490f0a4578732395da7bff3a7d0"

  strings:
    $s1 = "} while (iw++ < ta);" fullword ascii

  condition:
    uint16(0) == 0x0a0a and
    all of them
}