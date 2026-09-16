rule sig_20161024_ea881a378f06ed087bcbad967dfff539 {
  meta:
    description = "datamaliciousorder - file 20161024_ea881a378f06ed087bcbad967dfff539.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "89bbe0f961cc5529b22c7e8bbf10aa5c35a25c463613bbfcb24e28c033a3e2ca"

  strings:
    $s1 = "} while (ij++ < uf);" fullword ascii

  condition:
    uint16(0) == 0x0a0a and
    all of them
}