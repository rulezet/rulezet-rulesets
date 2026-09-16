rule sig_20161024_046a1cfdee0e5a4ee991b02aca666c5a {
  meta:
    description = "datamaliciousorder - file 20161024_046a1cfdee0e5a4ee991b02aca666c5a.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "46e6f11556d34746716133f281d90f4929ffc15d6d41f5d432570ee4b3645a6e"

  strings:
    $s1 = "} while (eq++ < gq);" fullword ascii

  condition:
    uint16(0) == 0x0a0a and
    all of them
}