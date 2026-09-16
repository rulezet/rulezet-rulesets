rule sig_20161024_e38a6d837defa8fa837fceafaead304c {
  meta:
    description = "datamaliciousorder - file 20161024_e38a6d837defa8fa837fceafaead304c.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "b06a58e1926630f8779958d23d819ffece32b1e79b5224ecac3cde70f8b964df"

  strings:
    $s1 = "} while (ib++ < yk0);" fullword ascii

  condition:
    uint16(0) == 0x0a0a and
    all of them
}