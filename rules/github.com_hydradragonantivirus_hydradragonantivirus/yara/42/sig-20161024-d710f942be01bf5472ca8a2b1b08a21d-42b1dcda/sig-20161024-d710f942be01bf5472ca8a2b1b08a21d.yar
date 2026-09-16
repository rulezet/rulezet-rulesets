rule sig_20161024_d710f942be01bf5472ca8a2b1b08a21d {
  meta:
    description = "datamaliciousorder - file 20161024_d710f942be01bf5472ca8a2b1b08a21d.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "0652292456650339dbeb18081161f51f6a2bf4709221614e995fd1956600b265"

  strings:
    $s1 = "} while (xi1++ < gx);" fullword ascii

  condition:
    uint16(0) == 0x0a0a and
    all of them
}