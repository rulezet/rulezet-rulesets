rule _20160921_37b52e41aabc93218d864c1665a33610_20160921_ee1327bdf201_4918 {
  meta:
    description = "datamaliciousorder - from files 20160921_37b52e41aabc93218d864c1665a33610.js, 20160921_ee1327bdf201e62d1f7ae5482cabbd90.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "c506490b3737e1b21522717204e4143ada427e9af58fe86e42ed31dfd0fde66a"
    hash2       = "91500ac726f9d2548dffc99162aeece9863dc7b928106d27a769e6bbf9439f81"

  strings:
    $s1 = "000(){return \"DYs\";})(),(function f000(){return \"Yv\";})(),(function f000(){return \"Rh\";})(),(function f000(){return \"XTn" ascii
    $s2 = "n \"Sv\";})(),(function f000(){return \"TKp\";})(),(function f000(){return \"WIj\";})(),(function f000(){return \"QDg\";})(),(fu" ascii
    $s3 = "function f000(){return \"MJq\";})(),(function f000(){return \"WIj\";})(),(function f000(){return \"IAa\";})(),(function f000(){r" ascii
    $s4 = "unction f000(){return \"Sv\";})(),(function f000(){return \"Km\";})(),(function f000(){return \"RPt\";})(),(function f000(){retu" ascii
    $s5 = "0(){return \"Yv\";})(),(function f000(){return \"Rh\";})(),(function f000(){return \"XTn\";})(),(function f000(){return \"GGn\";" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}