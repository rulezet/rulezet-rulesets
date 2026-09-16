rule sig_20161024_e0222398d7d7b6661bbc38fb4d6376ba {
  meta:
    description = "datamaliciousorder - file 20161024_e0222398d7d7b6661bbc38fb4d6376ba.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "63d6dc87eef930c53fb1f7ae1463553e1055eebb14551bed106ea594a7d488fc"

  strings:
    $s1 = "} while (ev++ < tq);" fullword ascii

  condition:
    uint16(0) == 0x0a0a and
    all of them
}