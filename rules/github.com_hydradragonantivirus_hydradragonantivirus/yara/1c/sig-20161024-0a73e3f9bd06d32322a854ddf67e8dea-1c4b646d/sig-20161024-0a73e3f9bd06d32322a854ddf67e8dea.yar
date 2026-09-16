rule sig_20161024_0a73e3f9bd06d32322a854ddf67e8dea {
  meta:
    description = "datamaliciousorder - file 20161024_0a73e3f9bd06d32322a854ddf67e8dea.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "f1c249e20e6c4c94eb7b5b76f42a923d800e8a1501881ab316cab8375dccf0a3"

  strings:
    $s1 = "} while (cn0++ < iw);" fullword ascii

  condition:
    uint16(0) == 0x0a0a and
    all of them
}