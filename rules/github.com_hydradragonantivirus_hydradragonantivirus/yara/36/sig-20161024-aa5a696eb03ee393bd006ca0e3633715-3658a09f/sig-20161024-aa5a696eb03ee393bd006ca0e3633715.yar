rule sig_20161024_aa5a696eb03ee393bd006ca0e3633715 {
  meta:
    description = "datamaliciousorder - file 20161024_aa5a696eb03ee393bd006ca0e3633715.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "bf914e35e278194d73221f5229e95bdca70d05d24a122fb299d86edde47007c9"

  strings:
    $s1 = "} while (nh++ < uq);" fullword ascii

  condition:
    uint16(0) == 0x0a0a and
    all of them
}