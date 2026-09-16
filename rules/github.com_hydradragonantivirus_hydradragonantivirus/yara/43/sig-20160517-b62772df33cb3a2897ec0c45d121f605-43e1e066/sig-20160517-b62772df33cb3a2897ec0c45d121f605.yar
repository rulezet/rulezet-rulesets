rule sig_20160517_b62772df33cb3a2897ec0c45d121f605 {
  meta:
    description = "datamaliciousorder - file 20160517_b62772df33cb3a2897ec0c45d121f605.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "ddd43b22c19be4454fe58e9129be47883537d461fe8041aadc2d83063a180e2e"

  strings:
    $s1 = "var d3qc3v='vag2jsafceh2rgaxsu yrt1nekm2nasv3213sehjwucbw1kdagqizjhtcb1dlyyuumrtcp1cqkunbr=whnjv\\'zlmektylqblcaxjssneryprighmsm" ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}