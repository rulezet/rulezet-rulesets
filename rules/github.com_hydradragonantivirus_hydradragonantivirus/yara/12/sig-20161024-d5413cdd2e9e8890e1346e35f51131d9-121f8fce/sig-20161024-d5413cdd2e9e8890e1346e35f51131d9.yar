rule sig_20161024_d5413cdd2e9e8890e1346e35f51131d9 {
  meta:
    description = "datamaliciousorder - file 20161024_d5413cdd2e9e8890e1346e35f51131d9.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "8fefc81dcd0a9b4c961bc7f0ee3208c8c98428bacab1195e05a8ef76a921683c"

  strings:
    $s1 = "} while (st++ < ee);" fullword ascii

  condition:
    uint16(0) == 0x0a0a and
    all of them
}