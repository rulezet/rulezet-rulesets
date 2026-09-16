rule sig_20161024_1246f577bca2810b35eef103de3466ed {
  meta:
    description = "datamaliciousorder - file 20161024_1246f577bca2810b35eef103de3466ed.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "78a988aa1723a54cb7485e795021fce577fd98ba723ca11435dd6eb57c865693"

  strings:
    $s1 = "} while (jj++ < hx);" fullword ascii

  condition:
    uint16(0) == 0x0a0a and
    all of them
}