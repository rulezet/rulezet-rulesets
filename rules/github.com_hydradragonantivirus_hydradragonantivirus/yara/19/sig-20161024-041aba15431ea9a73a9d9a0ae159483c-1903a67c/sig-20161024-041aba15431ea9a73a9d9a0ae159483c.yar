rule sig_20161024_041aba15431ea9a73a9d9a0ae159483c {
  meta:
    description = "datamaliciousorder - file 20161024_041aba15431ea9a73a9d9a0ae159483c.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "fdc7621e34b446e1fd87655dc950b29cb5439f8b5296526f86682ca161cdd5b1"

  strings:
    $s1 = "} while (rq++ < dm);" fullword ascii

  condition:
    uint16(0) == 0x0a0a and
    all of them
}