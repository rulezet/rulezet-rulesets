rule sig_20160523_3f9e57bf4e183ee5a3f14afc62824493 {
  meta:
    description = "datamaliciousorder - file 20160523_3f9e57bf4e183ee5a3f14afc62824493.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "30f4dc7d6c4d1fbd98a364f6d99798e205e967e17f83a1d40ec51f6613c27028"

  strings:
    $s1 = "verse().join('');" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}