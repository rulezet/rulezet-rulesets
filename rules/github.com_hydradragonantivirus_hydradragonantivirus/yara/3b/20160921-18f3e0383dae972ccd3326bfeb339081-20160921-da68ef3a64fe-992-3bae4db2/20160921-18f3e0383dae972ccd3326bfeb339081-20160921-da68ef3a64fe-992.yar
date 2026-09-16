rule _20160921_18f3e0383dae972ccd3326bfeb339081_20160921_da68ef3a64fe_992 {
  meta:
    description = "datamaliciousorder - from files 20160921_18f3e0383dae972ccd3326bfeb339081.js, 20160921_da68ef3a64fe9761a5f4505bcaef8f82.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "350a94fd53479bde96c18236897fe9846647bd4d4471ff812cc45a165d90a9d0"
    hash2       = "cecd93896e2d90bed54f31f9e387b5dcec7c277d5e455e561112b07c63d26ed5"

  strings:
    $s1  = "(),(function f000(){return \"Wy\";})(),(function f000(){return \"EZu\";})(),(function f000(){return \"Iq\";})(),(function f000()" ascii
    $s2  = "\";})(),(function f000(){return \"Sj\";})(),(function f000(){return \"Sq\";})(),(function f000(){return \"GGn\";})(),(function f" ascii
    $s3  = "x\";})(),(function f000(){return \"OMd\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"DYs\";})(),(functio" ascii
    $s4  = "\";})(),(function f000(){return \"ZFe\";})(),(function f000(){return \"DIa\";})(),(function f000(){return \"Zj\";})(),(function " ascii
    $s5  = "000(){return \"DNa\";})(),(function f000(){return \"Nx\";})(),(function f000(){return \"DIa\";})(),(function f000(){return \"Zj" ascii
    $s6  = "nction f000(){return \"Iq\";})(),(function f000(){return \"QDg\";})(),(function f000(){return \"DNa\";})(),(function f000(){retu" ascii
    $s7  = "0(){return \"KXg\";})(),(function f000(){return \"WIj\";})(),(function f000(){return \"Sv\";})(),(function f000(){return \"Lp\";" ascii
    $s8  = "on f000(){return \"DYx\";})(),(function f000(){return \"Ml\";})(),(function f000(){return \"PTi\";})(),(function f000(){return " ascii
    $s9  = "n \"BQb\";})(),(function f000(){return \"Oe\";})(),(function f000(){return \"QDg\";})(),(function f000(){return \"PTi\";})(),(fu" ascii
    $s10 = ";})(),(function f000(){return \"Go\";})(),(function f000(){return \"PTs\";})(),(function f000(){return \"Iq\";})(),(function f00" ascii
    $s11 = "\";})(),(function f000(){return \"KXg\";})(),(function f000(){return \"OUx\";})(),(function f000(){return \"Vu\";})(),(function " ascii
    $s12 = "on f000(){return \"WIj\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"Sj\";})(),(function f000(){return " ascii
    $s13 = "ction f000(){return \"QDg\";})(),(function f000(){return \"DYs\";})(),(function f000(){return \"IAa\";})(),(function f000(){retu" ascii
    $s14 = "nction f000(){return \"QDg\";})(),(function f000(){return \"PTi\";})(),(function f000(){return \"DNa\";})(),(function f000(){ret" ascii
    $s15 = "\"GGn\";})(),(function f000(){return \"DYs\";})(),(function f000(){return \"IAa\";})(),(function f000(){return \"Sq\";})(),(func" ascii
    $s16 = "return \"RPt\";})(),(function f000(){return \"Do\";})(),(function f000(){return \"KXg\";})(),(function f000(){return \"Qa\";})()" ascii
    $s17 = "f000(){return \"QDg\";})(),(function f000(){return \"DYs\";})(),(function f000(){return \"IAa\";})(),(function f000(){return \"S" ascii
    $s18 = "return \"GGn\";})(),(function f000(){return \"Sj\";})(),(function f000(){return \"Nx\";})(),(function f000(){return \"GGn\";})()" ascii
    $s19 = "n f000(){return \"GGn\";})(),(function f000(){return \"KXg\";})(),(function f000(){return \"Qa\";})(),(function f000(){return \"" ascii

  condition:
    (uint16(0) == 0x2f0a and (8 of them)
    ) or (all of them)
}