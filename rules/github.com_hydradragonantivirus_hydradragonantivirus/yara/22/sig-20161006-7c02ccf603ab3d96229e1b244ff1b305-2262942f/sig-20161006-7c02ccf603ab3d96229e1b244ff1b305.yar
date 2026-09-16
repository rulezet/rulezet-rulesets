rule sig_20161006_7c02ccf603ab3d96229e1b244ff1b305 {
  meta:
    description = "datamaliciousorder - file 20161006_7c02ccf603ab3d96229e1b244ff1b305.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "406e4ff3d6d990eceb5f3eb5f4306276f373734ffda44d55c019d0d0875fad83"

  strings:
    $s1 = "} while (gm++ < fe0);" fullword ascii

  condition:
    uint16(0) == 0x2f0a and
    all of them
}