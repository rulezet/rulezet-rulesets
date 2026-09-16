rule sig_20170323_05a3cc924d4c8c0699f8d72342482e51 {
  meta:
    description = "datamaliciousorder - file 20170323_05a3cc924d4c8c0699f8d72342482e51.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "947e4396463a5536a3b00a676441955c3a50bda959097e11b1115530a91b7ee2"

  strings:
    $s1 = "e.open(ih, ZHUL.concat(\"\"+kt+\"\")+kt+\"\"+zx+mter+zn+zn+tjkh+zn+\"c\"+\"o\"+\"u\"+\"nter\"+\"\"+gfyu+\"?\"+m, false);" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}