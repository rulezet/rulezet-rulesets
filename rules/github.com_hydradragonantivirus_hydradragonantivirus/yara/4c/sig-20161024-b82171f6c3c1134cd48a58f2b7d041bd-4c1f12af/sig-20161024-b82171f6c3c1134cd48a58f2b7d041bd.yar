rule sig_20161024_b82171f6c3c1134cd48a58f2b7d041bd {
  meta:
    description = "datamaliciousorder - file 20161024_b82171f6c3c1134cd48a58f2b7d041bd.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "ea4349e9932c2ebf56795c8e2511a2126823b63de9edacab72bcfba6d64e1c84"

  strings:
    $s1 = "} while (qt++ < qp);" fullword ascii

  condition:
    uint16(0) == 0x0a0a and
    all of them
}