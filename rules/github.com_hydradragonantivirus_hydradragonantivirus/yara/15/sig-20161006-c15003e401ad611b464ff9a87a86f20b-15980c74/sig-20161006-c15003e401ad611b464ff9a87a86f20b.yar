rule sig_20161006_c15003e401ad611b464ff9a87a86f20b {
  meta:
    description = "datamaliciousorder - file 20161006_c15003e401ad611b464ff9a87a86f20b.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "e1a9aed4cb172e587c94b82e15a22e6a771b97709629eac4411b1f955c1da947"

  strings:
    $s1 = "} while (dl++ < ow);" fullword ascii

  condition:
    uint16(0) == 0x2f0a and
    all of them
}