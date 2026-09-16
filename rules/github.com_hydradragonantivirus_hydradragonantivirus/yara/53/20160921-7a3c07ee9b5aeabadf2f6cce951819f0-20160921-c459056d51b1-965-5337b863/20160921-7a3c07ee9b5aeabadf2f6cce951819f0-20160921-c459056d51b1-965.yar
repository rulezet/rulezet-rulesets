rule _20160921_7a3c07ee9b5aeabadf2f6cce951819f0_20160921_c459056d51b1_965 {
  meta:
    description = "datamaliciousorder - from files 20160921_7a3c07ee9b5aeabadf2f6cce951819f0.js, 20160921_c459056d51b1a4ea3176139800021b35.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "f3f9ad4055c2ff243fcdf662544ac5eff6ef170765938a028b9c6e0029fcb2a7"
    hash2       = "2caf9c958877250774bdc190d1120c23a5fe115635a6c2d285aa8d62d171db39"

  strings:
    $s1  = "m\";})(),(function f000(){return \"Sq\";})(),(function f000(){return \"ZFe\";})(),(function f000(){return \"GGn\";})(),(function" ascii
    $s2  = "urn \"Ot\";})(),(function f000(){return \"Uo\";})(),(function f000(){return \"ZIi\";})(),(function f000(){return \"GGn\";})(),(f" ascii
    $s3  = "unction f000(){return \"Qp\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"DYs\";})(),(function f000(){ret" ascii
    $s4  = "),(function f000(){return \"WIj\";})(),(function f000(){return \"RPt\";})(),(function f000(){return \"Qa\";})(),(function f000()" ascii
    $s5  = "urn \"PTs\";})(),(function f000(){return \"Iq\";})(),(function f000(){return \"Do\";})(),(function f000(){return \"OUx\";})(),(f" ascii
    $s6  = "n f000(){return \"KXg\";})(),(function f000(){return \"Qa\";})(),(function f000(){return \"DIa\";})(),(function f000(){return \"" ascii
    $s7  = "),(function f000(){return \"Qa\";})(),(function f000(){return \"DIa\";})(),(function f000(){return \"GGn\";})(),(function f000()" ascii
    $s8  = "on f000(){return \"KXg\";})(),(function f000(){return \"ZFe\";})(),(function f000(){return \"Zj\";})(),(function f000(){return " ascii
    $s9  = ",(function f000(){return \"Ot\";})(),(function f000(){return \"DYs\";})(),(function f000(){return \"IAa\";})(),(function f000(){" ascii
    $s10 = "\";})(),(function f000(){return \"DNa\";})(),(function f000(){return \"Nx\";})(),(function f000(){return \"OMd\";})(),(function " ascii
    $s11 = "00(){return \"KXg\";})(),(function f000(){return \"Qa\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"Qp\"" ascii
    $s12 = "tion f000(){return \"DNa\";})(),(function f000(){return \"NYh\";})(),(function f000(){return \"Qa\";})(),(function f000(){return" ascii
    $s13 = "\";})(),(function f000(){return \"UEg\";})(),(function f000(){return \"TRc\";})(),(function f000(){return \"QDg\";})(),(function" ascii
    $s14 = "nction f000(){return \"Sv\";})(),(function f000(){return \"Lp\";})(),(function f000(){return \"Iq\";})(),(function f000(){return" ascii
    $s15 = "0(){return \"Ot\";})(),(function f000(){return \"Ot\";})(),(function f000(){return \"Ot\";})(),(function f000(){return \"Iq\";})" ascii
    $s16 = "{return \"MDb\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"IAa\";})(),(function f000(){return \"Rh\";})" ascii
    $s17 = "n \"Ut\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"RPt\";})(),(function f000(){return \"Do\";})(),(fun" ascii
    $s18 = "ction f000(){return \"Go\";})(),(function f000(){return \"RVb\";})(),(function f000(){return \"QDg\";})(),(function f000(){retur" ascii
    $s19 = "tion f000(){return \"Sq\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"QDg\";})(),(function f000(){return" ascii
    $s20 = "return \"GGn\";})(),(function f000(){return \"DYs\";})(),(function f000(){return \"IAa\";})(),(function f000(){return \"Sq\";})(" ascii

  condition:
    (uint16(0) == 0x2f0a and (8 of them)
    ) or (all of them)
}