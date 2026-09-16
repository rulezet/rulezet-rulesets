rule sig_20161024_65957deda53880110b22cb42d7b650c0 {
  meta:
    description = "datamaliciousorder - file 20161024_65957deda53880110b22cb42d7b650c0.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "6ddc2bd34c4cc323a6f600d307b7058201a0df0533a1dcfe093363db0217589f"

  strings:
    $s1 = "} while (lc++ < nd0);" fullword ascii

  condition:
    uint16(0) == 0x0a0a and
    all of them
}