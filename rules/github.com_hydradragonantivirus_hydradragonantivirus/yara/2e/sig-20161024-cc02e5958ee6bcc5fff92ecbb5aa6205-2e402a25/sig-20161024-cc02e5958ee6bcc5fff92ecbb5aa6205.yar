rule sig_20161024_cc02e5958ee6bcc5fff92ecbb5aa6205 {
  meta:
    description = "datamaliciousorder - file 20161024_cc02e5958ee6bcc5fff92ecbb5aa6205.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "ee9165c425a2099c14bd4c669487bdf35fea2f548366d456c9c7e84381165623"

  strings:
    $s1 = "} while (zz++ < bo);" fullword ascii

  condition:
    uint16(0) == 0x0a0a and
    all of them
}