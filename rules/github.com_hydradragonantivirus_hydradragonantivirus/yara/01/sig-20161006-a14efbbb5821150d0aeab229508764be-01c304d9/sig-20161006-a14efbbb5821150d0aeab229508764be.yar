rule sig_20161006_a14efbbb5821150d0aeab229508764be {
  meta:
    description = "datamaliciousorder - file 20161006_a14efbbb5821150d0aeab229508764be.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "1942faba9ca44c28c69641ab5e5ead6eb04c8a7586abd73eab214a6f264bfb21"

  strings:
    $s1 = "} while (dl++ < ow);" fullword ascii

  condition:
    uint16(0) == 0x2f0a and
    all of them
}