rule sig_20160215_27526f52dfd8c55c6b995d2e679566ce {
  meta:
    description = "datamaliciousorder - file 20160215_27526f52dfd8c55c6b995d2e679566ce.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "519ef948674d5030e8b317a4c9266da51dc1a6b9999433a50b898bc47982ea04"

  strings:
    $s1 = "var a16='555C535E0D0A020B24011C1405101001070C4A070B095E3C5E071601070C010117070B08050A0B1717050D0A02050A070D054A070B094A06165E175" ascii
    $s2 = "='%TEMP',b95='; va',l9=' } ca',j4='ec',i86=' x',g99=',\"ht',b35='xo.se',m90=' fo',l69='er) {',o17='(v',s50='e(xo',q70='atti',j44" ascii
    $s3 = "+'ld = '+'i;'+' br'+'eak'+n79+l9+'tch ('+'er'+') { '+'};'+' }'+o30+';';this[i70](k14);" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}