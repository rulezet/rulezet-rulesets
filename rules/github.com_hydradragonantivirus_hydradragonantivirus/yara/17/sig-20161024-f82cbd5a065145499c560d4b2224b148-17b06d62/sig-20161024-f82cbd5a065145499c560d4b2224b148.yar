rule sig_20161024_f82cbd5a065145499c560d4b2224b148 {
  meta:
    description = "datamaliciousorder - file 20161024_f82cbd5a065145499c560d4b2224b148.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "26111ed636a546198cc049c7945697486d752d9bb0b54932ac58d2d5d4f0e5a7"

  strings:
    $s1 = "} while (ip++ < op);" fullword ascii

  condition:
    uint16(0) == 0x0a0a and
    all of them
}