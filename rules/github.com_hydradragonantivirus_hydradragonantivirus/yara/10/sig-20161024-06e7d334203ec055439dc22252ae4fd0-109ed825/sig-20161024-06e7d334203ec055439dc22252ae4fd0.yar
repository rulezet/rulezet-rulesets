rule sig_20161024_06e7d334203ec055439dc22252ae4fd0 {
  meta:
    description = "datamaliciousorder - file 20161024_06e7d334203ec055439dc22252ae4fd0.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "d6482c89ad11e47cb93bc4968878b9323dfb83203b8d960aedbf1892f65df303"

  strings:
    $s1 = "} while (wu++ < xo);" fullword ascii

  condition:
    uint16(0) == 0x0a0a and
    all of them
}