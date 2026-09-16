rule sig_20161024_f7eac9263ee5991ffc14f982e1825ca3 {
  meta:
    description = "datamaliciousorder - file 20161024_f7eac9263ee5991ffc14f982e1825ca3.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "6b301ec57ff955a4ba9281460cdb22507286b22dd60d4922f52d60e59c0e4c59"

  strings:
    $s1 = "} while (tf++ < id);" fullword ascii

  condition:
    uint16(0) == 0x0a0a and
    all of them
}