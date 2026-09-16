rule sig_20161024_c88c4c4d9b161e559e254fef9bf54b08 {
  meta:
    description = "datamaliciousorder - file 20161024_c88c4c4d9b161e559e254fef9bf54b08.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "177005bd374e198a9c0a53331b4ed89b5f814f8afe948a8e6111430be163dbd5"

  strings:
    $s1 = "} while (qu++ < ms);" fullword ascii

  condition:
    uint16(0) == 0x0a0a and
    all of them
}