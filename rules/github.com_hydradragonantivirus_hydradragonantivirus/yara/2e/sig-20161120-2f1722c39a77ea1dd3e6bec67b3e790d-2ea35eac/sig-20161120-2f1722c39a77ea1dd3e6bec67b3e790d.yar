rule sig_20161120_2f1722c39a77ea1dd3e6bec67b3e790d {
  meta:
    description = "datamaliciousorder - file 20161120_2f1722c39a77ea1dd3e6bec67b3e790d.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "b92bf17673427bb01fcbcb68f54f01d13294e0250fa42005772cdefc774f946d"

  strings:
    $s1 = "var smuvjiwev = new Function(wiftezbyh8);" fullword ascii
    $s2 = "var bywyqqykxe22 = new Function(aqakgygjysk9)();" fullword ascii
    $s3 = "var iveqnyhi6 = new Function(ebhobsyh)();" fullword ascii
    $s4 = "switch (iveqnyhi6) {" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}