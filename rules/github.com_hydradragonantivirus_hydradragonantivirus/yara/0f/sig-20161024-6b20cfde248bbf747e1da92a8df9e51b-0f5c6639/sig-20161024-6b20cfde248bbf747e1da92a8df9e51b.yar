rule sig_20161024_6b20cfde248bbf747e1da92a8df9e51b {
  meta:
    description = "datamaliciousorder - file 20161024_6b20cfde248bbf747e1da92a8df9e51b.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "f8d7f04217b5f7a8590c9ca5e8bf14b6c13afa7c09bef695b0a00e27d2fe5d44"

  strings:
    $s1 = "} while (op++ < xu);" fullword ascii

  condition:
    uint16(0) == 0x0a0a and
    all of them
}