rule sig_20161024_31c99b22ef1d86825cae8a5a65921629 {
  meta:
    description = "datamaliciousorder - file 20161024_31c99b22ef1d86825cae8a5a65921629.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "8ac93c46d921a310825fb5c58888b977a4203e67658ee5ccd9009fb879353257"

  strings:
    $s1 = "} while (xo++ < ya);" fullword ascii

  condition:
    uint16(0) == 0x0a0a and
    all of them
}