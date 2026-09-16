rule sig_20161024_551e7ba72e28a60f2cafa8bb9ec7d8e1 {
  meta:
    description = "datamaliciousorder - file 20161024_551e7ba72e28a60f2cafa8bb9ec7d8e1.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "13a4bf638a83f7ad684a6ed51835c9f1e6e6d218942d55ffb87549edf56f1e97"

  strings:
    $s1 = "} while (rz++ < ue);" fullword ascii

  condition:
    uint16(0) == 0x0a0a and
    all of them
}