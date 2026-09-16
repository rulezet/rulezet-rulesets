rule sig_20161024_5c08786971c395620d96cc1121a63257 {
  meta:
    description = "datamaliciousorder - file 20161024_5c08786971c395620d96cc1121a63257.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "e31433c078eee4a824546bbf8eda8c22589565eedf5ec035098354ddc126fca6"

  strings:
    $s1 = "} while (mm0++ < nx);" fullword ascii

  condition:
    uint16(0) == 0x0a0a and
    all of them
}