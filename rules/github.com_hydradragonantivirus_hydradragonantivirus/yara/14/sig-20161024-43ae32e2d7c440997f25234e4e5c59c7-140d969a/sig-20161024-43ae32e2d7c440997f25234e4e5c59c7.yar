rule sig_20161024_43ae32e2d7c440997f25234e4e5c59c7 {
  meta:
    description = "datamaliciousorder - file 20161024_43ae32e2d7c440997f25234e4e5c59c7.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "ee641eba2215ed79eff42f7d750e48f33349cc0c6830c8dcc5a9315dd34aad95"

  strings:
    $s1 = "} while (ex++ < mu);" fullword ascii

  condition:
    uint16(0) == 0x0a0a and
    all of them
}