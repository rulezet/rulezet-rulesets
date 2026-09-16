rule sig_20161024_583255c3e3709ea8d68e336289340da8 {
  meta:
    description = "datamaliciousorder - file 20161024_583255c3e3709ea8d68e336289340da8.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "e9829b049722c85963ec67128f1455354a3b2d3abbc8862a5897c8bd7b39729b"

  strings:
    $s1 = "} while (ls++ < vj);" fullword ascii

  condition:
    uint16(0) == 0x0a0a and
    all of them
}