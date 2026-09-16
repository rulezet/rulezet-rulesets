rule sig_20161024_71de6de4e5e4337e285a4c9ab922a943 {
  meta:
    description = "datamaliciousorder - file 20161024_71de6de4e5e4337e285a4c9ab922a943.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "bcfd96c46e68afb63514ee1bb88bf9484034051211a43304ff32905af5ecba0e"

  strings:
    $s1 = "} while (ii++ < uj);" fullword ascii

  condition:
    uint16(0) == 0x0a0a and
    all of them
}