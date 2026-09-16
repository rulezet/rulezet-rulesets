rule sig_20161024_69a1653b8f671cbfc56f846dfc200f7c {
  meta:
    description = "datamaliciousorder - file 20161024_69a1653b8f671cbfc56f846dfc200f7c.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "668befebebfa292f471d00edca6b81cc239bf4afe45e28f4ce0b204e14fb4503"

  strings:
    $s1 = "} while (kd++ < cw);" fullword ascii

  condition:
    uint16(0) == 0x0a0a and
    all of them
}