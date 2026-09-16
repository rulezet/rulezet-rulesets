rule sig_20161024_a2b0e5a51c4633f286dc716682b47866 {
  meta:
    description = "datamaliciousorder - file 20161024_a2b0e5a51c4633f286dc716682b47866.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "72182a4f6d6356af0816f982881f73c5e57a17e1a790f112ad27c91f732b8bd9"

  strings:
    $s1 = "} while (mc++ < ug);" fullword ascii

  condition:
    uint16(0) == 0x0a0a and
    all of them
}