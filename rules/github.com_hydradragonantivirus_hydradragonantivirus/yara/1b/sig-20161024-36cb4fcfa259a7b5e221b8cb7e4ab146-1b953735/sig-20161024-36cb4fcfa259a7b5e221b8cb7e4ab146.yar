rule sig_20161024_36cb4fcfa259a7b5e221b8cb7e4ab146 {
  meta:
    description = "datamaliciousorder - file 20161024_36cb4fcfa259a7b5e221b8cb7e4ab146.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "6e4a65362292d161a9b226bdd0877945348d63bf52e8a72f88ac372d650ece3e"

  strings:
    $s1 = "} while (pc++ < cy);" fullword ascii

  condition:
    uint16(0) == 0x0a0a and
    all of them
}