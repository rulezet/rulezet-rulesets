rule sig_20161024_bb62c64f28c14027ba6be8fce4e99ab3 {
  meta:
    description = "datamaliciousorder - file 20161024_bb62c64f28c14027ba6be8fce4e99ab3.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "fa4154d874935623738c5216d86eb93ad774bd87ace61cc1c2e26e9260409845"

  strings:
    $s1 = "} while (ib++ < fu);" fullword ascii

  condition:
    uint16(0) == 0x0a0a and
    all of them
}