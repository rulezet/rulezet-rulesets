rule sig_20161024_c716a2c5876ad15f0b023305306f1d47 {
  meta:
    description = "datamaliciousorder - file 20161024_c716a2c5876ad15f0b023305306f1d47.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "0a0be34465a1563bd4680e76265f57955b334b20eff2101a75dd941ca15fba42"

  strings:
    $s1 = "} while (ni++ < un);" fullword ascii

  condition:
    uint16(0) == 0x0a0a and
    all of them
}