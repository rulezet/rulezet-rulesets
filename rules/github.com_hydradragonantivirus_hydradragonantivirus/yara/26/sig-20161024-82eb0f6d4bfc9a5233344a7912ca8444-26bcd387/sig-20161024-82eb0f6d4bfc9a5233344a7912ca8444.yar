rule sig_20161024_82eb0f6d4bfc9a5233344a7912ca8444 {
  meta:
    description = "datamaliciousorder - file 20161024_82eb0f6d4bfc9a5233344a7912ca8444.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "460d2e52ba13dd882cde176d036c7744b2a9885d1b73aae0c695cbcc4fd5b707"

  strings:
    $s1 = "} while (kz++ < wu);" fullword ascii

  condition:
    uint16(0) == 0x0a0a and
    all of them
}