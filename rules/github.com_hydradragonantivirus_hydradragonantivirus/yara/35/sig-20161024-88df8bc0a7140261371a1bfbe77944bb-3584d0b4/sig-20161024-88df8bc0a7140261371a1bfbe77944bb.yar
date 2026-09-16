rule sig_20161024_88df8bc0a7140261371a1bfbe77944bb {
  meta:
    description = "datamaliciousorder - file 20161024_88df8bc0a7140261371a1bfbe77944bb.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "c76260f4747a7540c7d534ee0fcfbed784cf3e73c3d6c6c41dc11e634299c2cc"

  strings:
    $s1 = "} while (wn++ < pa);" fullword ascii

  condition:
    uint16(0) == 0x0a0a and
    all of them
}