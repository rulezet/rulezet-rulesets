rule sig_20161024_6a205151236b5879b578ef72718b2c14 {
  meta:
    description = "datamaliciousorder - file 20161024_6a205151236b5879b578ef72718b2c14.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "cecbeda6b938c34a4638ed364eb21bc22d3b283550e9e2dbeaef813e6221d40b"

  strings:
    $s1 = "} while (ij++ < uf);" fullword ascii

  condition:
    uint16(0) == 0x0a0a and
    all of them
}