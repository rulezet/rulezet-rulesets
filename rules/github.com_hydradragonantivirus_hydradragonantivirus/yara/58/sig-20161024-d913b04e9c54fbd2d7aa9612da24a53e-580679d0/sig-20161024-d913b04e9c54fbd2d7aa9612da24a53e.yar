rule sig_20161024_d913b04e9c54fbd2d7aa9612da24a53e {
  meta:
    description = "datamaliciousorder - file 20161024_d913b04e9c54fbd2d7aa9612da24a53e.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "40261f1ec191485faa91de1a6a0749deb558be2cf1cabf244a5a697fe1434c03"

  strings:
    $s1 = "} while (hy++ < io);" fullword ascii

  condition:
    uint16(0) == 0x0a0a and
    all of them
}