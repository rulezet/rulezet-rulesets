rule _20160921_f9054cc04d83c2e4156f98873a8df799_20160921_fbc9133aa535_61 {
  meta:
    description = "datamaliciousorder - from files 20160921_f9054cc04d83c2e4156f98873a8df799.js, 20160921_fbc9133aa5350aa4ce872cb5927c8f4f.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "7cfaa97d52690e3fa38d039126186e468701b138b24622f48887707d5da022f0"
    hash2       = "520ea6f275b172709ff81bfec4d8a5a9f734ab080b25e7c50bfe2a36800af6e3"

  strings:
    $s1  = "})(),(function f000(){return \"DYx\";})(),(function f000(){return \"TKp\";})(),(function f000(){return \"Br\";})(),(function f00" ascii
    $s2  = "ion f000(){return \"Sv\";})(),(function f000(){return \"Wb\";})(),(function f000(){return \"ZGq\";})(),(function f000(){return " ascii
    $s3  = "c\";})(),(function f000(){return \"Wy\";})(),(function f000(){return \"OUx\";})(),(function f000(){return \"Go\";})(),(function " ascii
    $s4  = "rn \"MDb\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"Uo\";})(),(function f000(){return \"Oe\";})(),(fu" ascii
    $s5  = " f000(){return \"ZFe\";})(),(function f000(){return \"IPu\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"" ascii
    $s6  = "on f000(){return \"Ot\";})(),(function f000(){return \"Ot\";})(),(function f000(){return \"Um\";})(),(function f000(){return \"G" ascii
    $s7  = " f000(){return \"PTi\";})(),(function f000(){return \"DYx\";})(),(function f000(){return \"MDb\";})(),(function f000(){return \"" ascii
    $s8  = "\"TKl\";})(),(function f000(){return \"WIj\";})(),(function f000(){return \"OUx\";})(),(function f000(){return \"Go\";})(),(func" ascii
    $s9  = "return \"ZGq\";})(),(function f000(){return \"TKl\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"MDb\";})" ascii
    $s10 = "unction f000(){return \"ZFe\";})(),(function f000(){return \"Km\";})(),(function f000(){return \"GGn\";})(),(function f000(){ret" ascii
    $s11 = "on f000(){return \"KXg\";})(),(function f000(){return \"MDb\";})(),(function f000(){return \"HJm\";})(),(function f000(){return " ascii
    $s12 = "n \"GGn\";})(),(function f000(){return \"DNa\";})(),(function f000(){return \"ZIi\";})(),(function f000(){return \"Tn\";})(),(fu" ascii
    $s13 = "return \"RPt\";})(),(function f000(){return \"XTn\";})(),(function f000(){return \"Lp\";})(),(function f000(){return \"Zj\";})()" ascii
    $s14 = " f000(){return \"IAa\";})(),(function f000(){return \"EZu\";})(),(function f000(){return \"ZGq\";})(),(function f000(){return \"" ascii
    $s15 = "rn \"Yi\";})(),(function f000(){return \"Kw\";})(),(function f000(){return \"Yi\";})(),(function f000(){return \"ZGq\";})(),(fun" ascii
    $s16 = "Gn\";})(),(function f000(){return \"Br\";})(),(function f000(){return \"KXg\";})(),(function f000(){return \"MJq\";})(),(functio" ascii
    $s17 = "unction f000(){return \"RPt\";})(),(function f000(){return \"Qj\";})(),(function f000(){return \"Yi\";})(),(function f000(){retu" ascii
    $s18 = "(),(function f000(){return \"UEg\";})(),(function f000(){return \"MDb\";})(),(function f000(){return \"RLk\";})(),(function f000" ascii
    $s19 = " \"GGn\";})(),(function f000(){return \"Do\";})(),(function f000(){return \"MKa\";})(),(function f000(){return \"KDh\";})(),(fun" ascii
    $s20 = " \"MDb\";})(),(function f000(){return \"Yv\";})(),(function f000(){return \"MMz\";})(),(function f000(){return \"Mt\";})(),(func" ascii

  condition:
    (uint16(0) == 0x2f0a and (8 of them)
    ) or (all of them)
}