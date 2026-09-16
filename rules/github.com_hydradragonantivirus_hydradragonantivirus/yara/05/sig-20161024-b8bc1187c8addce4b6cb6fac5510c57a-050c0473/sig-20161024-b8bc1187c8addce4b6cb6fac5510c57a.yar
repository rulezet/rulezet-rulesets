rule sig_20161024_b8bc1187c8addce4b6cb6fac5510c57a {
  meta:
    description = "datamaliciousorder - file 20161024_b8bc1187c8addce4b6cb6fac5510c57a.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "679382e38f8ed7c69652e66a122f42d720d0b711feed4439b123cdaa2a10e59c"

  strings:
    $s1 = "} while (dl++ < yl);" fullword ascii

  condition:
    uint16(0) == 0x0a0a and
    all of them
}