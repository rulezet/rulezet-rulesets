rule sig_20161024_a98de11a12d3e1e86944dcd859ba47f1 {
  meta:
    description = "datamaliciousorder - file 20161024_a98de11a12d3e1e86944dcd859ba47f1.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "9edf6f1891d7be57166dccc72f3e1526eb13ce6a885ad195678e487348514cf1"

  strings:
    $s1 = "} while (ih++ < iu);" fullword ascii

  condition:
    uint16(0) == 0x0a0a and
    all of them
}