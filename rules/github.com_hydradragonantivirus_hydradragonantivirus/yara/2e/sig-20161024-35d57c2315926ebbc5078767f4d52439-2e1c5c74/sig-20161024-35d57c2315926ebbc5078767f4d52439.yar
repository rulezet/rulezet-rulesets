rule sig_20161024_35d57c2315926ebbc5078767f4d52439 {
  meta:
    description = "datamaliciousorder - file 20161024_35d57c2315926ebbc5078767f4d52439.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "54493a159902b60dd5d6199599efb36569aed5dbffe1ab4a384ab8e6dd75a791"

  strings:
    $s1 = "} while (ie0++ < eb);" fullword ascii

  condition:
    uint16(0) == 0x0a0a and
    all of them
}