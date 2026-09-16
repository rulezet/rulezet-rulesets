rule sig_20161024_b46910e0252022fc9af7db9f66aba9dd {
  meta:
    description = "datamaliciousorder - file 20161024_b46910e0252022fc9af7db9f66aba9dd.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "43267137d6027f4f0db850afa4cde13d3c6defff8f1ab1a27fab887186339f5f"

  strings:
    $s1 = "} while (gv++ < mu);" fullword ascii

  condition:
    uint16(0) == 0x0a0a and
    all of them
}