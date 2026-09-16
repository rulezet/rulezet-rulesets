rule sig_20161024_55675c74cb4443e7e52dacf6dcf29b89 {
  meta:
    description = "datamaliciousorder - file 20161024_55675c74cb4443e7e52dacf6dcf29b89.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "8b8cde7f9c6e0ca43554ed48433821fa9ace40c45b04ab64b5c630525d0c7e57"

  strings:
    $s1 = "} while (pk++ < vj);" fullword ascii

  condition:
    uint16(0) == 0x0a0a and
    all of them
}