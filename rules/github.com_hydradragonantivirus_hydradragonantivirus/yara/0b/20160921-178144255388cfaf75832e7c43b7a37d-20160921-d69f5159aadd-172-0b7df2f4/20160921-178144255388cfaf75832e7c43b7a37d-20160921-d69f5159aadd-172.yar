rule _20160921_178144255388cfaf75832e7c43b7a37d_20160921_d69f5159aadd_172 {
  meta:
    description = "datamaliciousorder - from files 20160921_178144255388cfaf75832e7c43b7a37d.js, 20160921_d69f5159aadd1440760083d8952604c6.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "ceb222ab2a29064bfa74287cfdb14daf49b9474ead74db04adbe122341895903"
    hash2       = "6a93de0a10bfc4b55037c85e12bc3eb9699d5353c4a13a206b5e16e7303d5c86"

  strings:
    $s1  = "on f000(){return \"Do\";})(),(function f000(){return \"KXg\";})(),(function f000(){return \"Lp\";})(),(function f000(){return \"" ascii
    $s2  = "00(){return \"IPu\";})(),(function f000(){return \"XTn\";})(),(function f000(){return \"MDb\";})(),(function f000(){return \"Nv" ascii
    $s3  = "(),(function f000(){return \"Qp\";})(),(function f000(){return \"Qp\";})(),(function f000(){return \"GGn\";})(),(function f000()" ascii
    $s4  = "DYs\";})(),(function f000(){return \"YTp\";})(),(function f000(){return \"Yi\";})(),(function f000(){return \"GGn\";})(),(functi" ascii
    $s5  = "ion f000(){return \"Br\";})(),(function f000(){return \"DYx\";})(),(function f000(){return \"Br\";})(),(function f000(){return " ascii
    $s6  = ")(),(function f000(){return \"MDb\";})(),(function f000(){return \"ZFe\";})(),(function f000(){return \"IPu\";})(),(function f00" ascii
    $s7  = "n\";})(),(function f000(){return \"Um\";})(),(function f000(){return \"EZu\";})(),(function f000(){return \"Qj\";})(),(function " ascii
    $s8  = "unction f000(){return \"ZFe\";})(),(function f000(){return \"PTi\";})(),(function f000(){return \"Iq\";})(),(function f000(){ret" ascii
    $s9  = "turn \"Ot\";})(),(function f000(){return \"Ot\";})(),(function f000(){return \"Ot\";})(),(function f000(){return \"MMz\";})(),(f" ascii
    $s10 = "s\";})(),(function f000(){return \"Km\";})(),(function f000(){return \"MDb\";})(),(function f000(){return \"DNa\";})(),(function" ascii
    $s11 = "Gn\";})(),(function f000(){return \"KXg\";})(),(function f000(){return \"Yi\";})(),(function f000(){return \"Do\";})(),(function" ascii
    $s12 = "000(){return \"OUx\";})(),(function f000(){return \"SEo\";})(),(function f000(){return \"ZGq\";})(),(function f000(){return \"DY" ascii
    $s13 = "\"GGn\";})(),(function f000(){return \"PTs\";})(),(function f000(){return \"Um\";})(),(function f000(){return \"NBs\";})(),(func" ascii
    $s14 = " \"GGn\";})(),(function f000(){return \"IAa\";})(),(function f000(){return \"TKp\";})(),(function f000(){return \"RPt\";})(),(fu" ascii
    $s15 = "(function f000(){return \"Wb\";})(),(function f000(){return \"XTn\";})(),(function f000(){return \"GGn\";})(),(function f000(){r" ascii
    $s16 = "})(),(function f000(){return \"Mu\";})(),(function f000(){return \"Lp\";})(),(function f000(){return \"TRc\";})(),(function f000" ascii
    $s17 = "ction f000(){return \"MDb\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"Nv\";})(),(function f000(){retur" ascii
    $s18 = "\";})(),(function f000(){return \"TKl\";})(),(function f000(){return \"MDb\";})(),(function f000(){return \"Nv\";})(),(function " ascii
    $s19 = "turn \"Tn\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"Sj\";})(),(function f000(){return \"Km\";})(),(f" ascii
    $s20 = "})(),(function f000(){return \"Uo\";})(),(function f000(){return \"Wy\";})(),(function f000(){return \"TKl\";})(),(function f000" ascii

  condition:
    (uint16(0) == 0x2f0a and (8 of them)
    ) or (all of them)
}