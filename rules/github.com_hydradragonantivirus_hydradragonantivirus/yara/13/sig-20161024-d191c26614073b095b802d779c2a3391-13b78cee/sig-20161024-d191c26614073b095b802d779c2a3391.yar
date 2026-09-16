rule sig_20161024_d191c26614073b095b802d779c2a3391 {
  meta:
    description = "datamaliciousorder - file 20161024_d191c26614073b095b802d779c2a3391.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "6249d5b52d67f51bc23f1a93b2df1d265c0a74fa87e2cf7902b307c6557ec2b3"

  strings:
    $s1 = "} while (ni++ < xk);" fullword ascii

  condition:
    uint16(0) == 0x0a0a and
    all of them
}