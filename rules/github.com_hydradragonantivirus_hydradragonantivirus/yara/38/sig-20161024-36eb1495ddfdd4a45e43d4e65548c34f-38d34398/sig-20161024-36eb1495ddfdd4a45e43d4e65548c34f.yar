rule sig_20161024_36eb1495ddfdd4a45e43d4e65548c34f {
  meta:
    description = "datamaliciousorder - file 20161024_36eb1495ddfdd4a45e43d4e65548c34f.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "59b58769214bd26a4980348e0e0d988fe05ccd604dde4b2c71248b1a9da62796"

  strings:
    $s1 = "} while (hw0++ < vm);" fullword ascii

  condition:
    uint16(0) == 0x0a0a and
    all of them
}