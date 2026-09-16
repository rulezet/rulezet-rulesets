rule sig_20161024_7df971435ea6daffa855219be40c27f1 {
  meta:
    description = "datamaliciousorder - file 20161024_7df971435ea6daffa855219be40c27f1.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "19b5a1df21588fc521881f7b90d1187958d8fd72a608c25ea663dd58403eb4c7"

  strings:
    $s1 = "} while (ld++ < wm);" fullword ascii

  condition:
    uint16(0) == 0x0a0a and
    all of them
}