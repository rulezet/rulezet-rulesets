rule sig_20160208_977c06db733bb17b3d003f06ac0a5234 {
  meta:
    description = "datamaliciousorder - file 20160208_977c06db733bb17b3d003f06ac0a5234.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "ec3fc09556aa803305bd7dee344e74a1cbcb75deae221799c04cff1c4a926751"

  strings:
    $s1 = "'n' + ('o8MFYa', '34RYy', 'przo', 'g') + 'e'] = function() {" fullword ascii
    $s2 = "    auIewPxrE['onr' + ('D6jm', 'tzOI', 'gEOTy', 'e') + 'a' + ('lO4Hr5', 'D3o', 'PY1t5', 'd') + 'y' + ('xOqlx4', 'bTwKW', '5Lq', " ascii

  condition:
    uint16(0) == 0x0a0d and
    all of them
}