rule sig_20161024_cf0472fac950bb6a4727a8f3294f788a {
  meta:
    description = "datamaliciousorder - file 20161024_cf0472fac950bb6a4727a8f3294f788a.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "bda2c93eb984cea859488601b92d7d256fee9c370840e2cb51bbd10eaf82c03e"

  strings:
    $s1 = "} while (in0++ < db);" fullword ascii

  condition:
    uint16(0) == 0x0a0a and
    all of them
}