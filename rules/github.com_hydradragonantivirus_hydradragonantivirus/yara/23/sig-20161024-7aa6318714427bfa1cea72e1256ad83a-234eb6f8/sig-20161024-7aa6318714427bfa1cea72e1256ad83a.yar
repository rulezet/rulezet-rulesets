rule sig_20161024_7aa6318714427bfa1cea72e1256ad83a {
  meta:
    description = "datamaliciousorder - file 20161024_7aa6318714427bfa1cea72e1256ad83a.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "6bc11bfc95147213a834edb1e62c441cacad346c9521b77ac0a0766c95f3e003"

  strings:
    $s1 = "} while (uf++ < xo);" fullword ascii

  condition:
    uint16(0) == 0x0a0a and
    all of them
}