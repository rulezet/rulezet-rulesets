rule sig_20161024_89747af65e6d3346512c690068d362e2 {
  meta:
    description = "datamaliciousorder - file 20161024_89747af65e6d3346512c690068d362e2.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "761816287225b7b68c2d9cc6ae991cda181d8b5bad694d028a0726750e96567a"

  strings:
    $s1 = "} while (ek++ < we);" fullword ascii

  condition:
    uint16(0) == 0x0a0a and
    all of them
}