rule sig_20161024_a009e4979af2d6b5e90ccffc20c49942 {
  meta:
    description = "datamaliciousorder - file 20161024_a009e4979af2d6b5e90ccffc20c49942.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "0130464d9ee144631132f35b3ac0761ad21470a3f2dc56e835d7623ce76418e5"

  strings:
    $s1 = "} while (ba++ < qp);" fullword ascii

  condition:
    uint16(0) == 0x0a0a and
    all of them
}