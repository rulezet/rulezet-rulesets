rule sig_20160920_323954f4579174d67d1150ff34d16cd6 {
  meta:
    description = "datamaliciousorder - file 20160920_323954f4579174d67d1150ff34d16cd6.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "fa0e1be63f49a2d8eb5395fd14a3a6f690e4866e479a98f425497fba0866d27b"

  strings:
    $s1 = "split('msemse');" fullword ascii

  condition:
    uint16(0) == 0x2f0a and
    all of them
}