rule sig_20161024_6bb377dd1872669075b88744afb59814 {
  meta:
    description = "datamaliciousorder - file 20161024_6bb377dd1872669075b88744afb59814.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "b815ec6e1467dbe5072d19bd4fc74956cc8172e9c25fe9d9c01652756437347d"

  strings:
    $s1 = "} while (gq++ < jp);" fullword ascii

  condition:
    uint16(0) == 0x0a0a and
    all of them
}