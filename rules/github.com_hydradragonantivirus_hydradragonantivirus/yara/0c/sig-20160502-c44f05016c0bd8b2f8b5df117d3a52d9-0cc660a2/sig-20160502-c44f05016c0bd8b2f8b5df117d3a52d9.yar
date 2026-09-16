rule sig_20160502_c44f05016c0bd8b2f8b5df117d3a52d9 {
  meta:
    description = "datamaliciousorder - file 20160502_c44f05016c0bd8b2f8b5df117d3a52d9.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "e8e3b25cd7eeeb92db1ac4e8bd7d53976fe59ecd1f1e0a5d576d455098b13194"

  strings:
    $s1 = "scad';o38+='bac';var s36='.cl';o38+='kup ';var h81='%CO';o38+='*.';var k36='ypt';o38+='mdb ';var r89=' *.';o38+='*.a';var o8=' F" ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}