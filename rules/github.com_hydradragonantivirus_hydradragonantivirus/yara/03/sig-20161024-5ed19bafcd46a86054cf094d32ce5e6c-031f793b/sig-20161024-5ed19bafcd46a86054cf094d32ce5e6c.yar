rule sig_20161024_5ed19bafcd46a86054cf094d32ce5e6c {
  meta:
    description = "datamaliciousorder - file 20161024_5ed19bafcd46a86054cf094d32ce5e6c.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "305ad0a09dd7a21342d23500783547d032242b679e3701d22c52392901ab416c"

  strings:
    $s1 = "} while (qo++ < aa);" fullword ascii

  condition:
    uint16(0) == 0x0a0a and
    all of them
}