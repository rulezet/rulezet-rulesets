rule _20160921_37b52e41aabc93218d864c1665a33610_20160921_d74d6a32efd0_3636 {
  meta:
    description = "datamaliciousorder - from files 20160921_37b52e41aabc93218d864c1665a33610.js, 20160921_d74d6a32efd0c1fd568c81769c75b5f0.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "c506490b3737e1b21522717204e4143ada427e9af58fe86e42ed31dfd0fde66a"
    hash2       = "eeb2c0427dff61d2dceedf890b96f76da6a37634fefa03079a481c476d7a3547"

  strings:
    $s1 = "rn \"Kw\";})(),(function f000(){return \"Vj\";})(),(function f000(){return \"TRc\";})(),(function f000(){return \"WIj\";})(),(fu" ascii
    $s2 = "(),(function f000(){return \"Vj\";})(),(function f000(){return \"Vu\";})(),(function f000(){return \"Kw\";})(),(function f000(){" ascii
    $s3 = "nction f000(){return \"XTn\";})(),(function f000(){return \"Vu\";})(),(function f000(){return \"TRc\";})(),(function f000(){retu" ascii
    $s4 = ";})(),(function f000(){return \"Kw\";})(),(function f000(){return \"TKl\";})(),(function f000(){return \"Vu\";})(),(function f00" ascii
    $s5 = "n f000(){return \"MKa\";})(),(function f000(){return \"KZr\";})(),(function f000(){return \"Zj\";})(),(function f000(){return \"" ascii
    $s6 = "tion f000(){return \"Vj\";})(),(function f000(){return \"Vj\";})(),(function f000(){return \"RPt\";})(),(function f000(){return " ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}