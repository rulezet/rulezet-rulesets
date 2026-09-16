rule sig_20161006_c78989ff129c099a3798901ec8373ee6 {
  meta:
    description = "datamaliciousorder - file 20161006_c78989ff129c099a3798901ec8373ee6.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "052d94099f5d3eecd948fa04ab29b632dc10d86318e8e127468654418e8a769f"

  strings:
    $s1 = "} while (dl++ < ow);" fullword ascii

  condition:
    uint16(0) == 0x2f0a and
    all of them
}