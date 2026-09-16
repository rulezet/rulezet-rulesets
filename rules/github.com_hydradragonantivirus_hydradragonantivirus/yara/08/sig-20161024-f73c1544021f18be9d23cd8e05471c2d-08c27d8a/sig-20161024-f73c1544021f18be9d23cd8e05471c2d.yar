rule sig_20161024_f73c1544021f18be9d23cd8e05471c2d {
  meta:
    description = "datamaliciousorder - file 20161024_f73c1544021f18be9d23cd8e05471c2d.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "c34bac6471fdb1837433b1867834938ba27df3ae3314227922e8dc520b37436c"

  strings:
    $s1 = "} while (xx0++ < bs0);" fullword ascii

  condition:
    uint16(0) == 0x0a0a and
    all of them
}