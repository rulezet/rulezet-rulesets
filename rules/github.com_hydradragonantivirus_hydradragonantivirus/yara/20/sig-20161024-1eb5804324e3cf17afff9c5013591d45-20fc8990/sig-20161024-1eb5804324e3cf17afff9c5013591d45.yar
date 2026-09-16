rule sig_20161024_1eb5804324e3cf17afff9c5013591d45 {
  meta:
    description = "datamaliciousorder - file 20161024_1eb5804324e3cf17afff9c5013591d45.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "bdc49d97ec11843bf4538e7474026964bb64dad7bb083a5a3587a9706e57dac3"

  strings:
    $s1 = "} while (in0++ < lx0);" fullword ascii

  condition:
    uint16(0) == 0x0a0a and
    all of them
}