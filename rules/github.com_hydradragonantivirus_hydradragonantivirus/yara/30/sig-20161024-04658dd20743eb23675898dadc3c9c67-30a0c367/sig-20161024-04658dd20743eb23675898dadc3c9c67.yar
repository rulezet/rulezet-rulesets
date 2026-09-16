rule sig_20161024_04658dd20743eb23675898dadc3c9c67 {
  meta:
    description = "datamaliciousorder - file 20161024_04658dd20743eb23675898dadc3c9c67.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "c20766115c98dfbabec169b8dd761b3b91a337ad57f1b884cf963fb247ead30c"

  strings:
    $s1 = "} while (as++ < do0);" fullword ascii

  condition:
    uint16(0) == 0x0a0a and
    all of them
}