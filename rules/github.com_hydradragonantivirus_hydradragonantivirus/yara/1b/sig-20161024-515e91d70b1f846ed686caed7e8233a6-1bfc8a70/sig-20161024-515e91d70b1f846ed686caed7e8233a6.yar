rule sig_20161024_515e91d70b1f846ed686caed7e8233a6 {
  meta:
    description = "datamaliciousorder - file 20161024_515e91d70b1f846ed686caed7e8233a6.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "69a2fe9d7c48ba45019d8eb9158a64080474d88686fa03de5c0bf177b2929876"

  strings:
    $s1 = "} while (ul++ < ui);" fullword ascii

  condition:
    uint16(0) == 0x0a0a and
    all of them
}