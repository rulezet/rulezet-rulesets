rule sig_20161024_a08c82ba231d285eb782b6c326bdeb46 {
  meta:
    description = "datamaliciousorder - file 20161024_a08c82ba231d285eb782b6c326bdeb46.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "2ce413968683f2bb475884c133e10bbb2a45a6fd4626edcd947aa23dca47c3e0"

  strings:
    $s1 = "} while (kw++ < vr0);" fullword ascii

  condition:
    uint16(0) == 0x0a0a and
    all of them
}