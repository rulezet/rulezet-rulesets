rule sig_20161024_7d0e7b1ea6dc312fe72a40c9f7f3a323 {
  meta:
    description = "datamaliciousorder - file 20161024_7d0e7b1ea6dc312fe72a40c9f7f3a323.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "bc4a045da84dd85b6eea7253fc0ab0d99763251f9f75f0c17d231a2c77ad8568"

  strings:
    $s1 = "} while (dt++ < uy);" fullword ascii

  condition:
    uint16(0) == 0x0a0a and
    all of them
}