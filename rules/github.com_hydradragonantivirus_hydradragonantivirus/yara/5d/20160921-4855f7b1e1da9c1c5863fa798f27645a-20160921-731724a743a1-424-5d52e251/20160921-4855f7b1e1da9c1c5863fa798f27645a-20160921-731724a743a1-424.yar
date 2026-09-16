rule _20160921_4855f7b1e1da9c1c5863fa798f27645a_20160921_731724a743a1_424 {
  meta:
    description = "datamaliciousorder - from files 20160921_4855f7b1e1da9c1c5863fa798f27645a.js, 20160921_731724a743a10eb03d2ee3a92239f369.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "3c9b29105af371fead56301baf1fdec90bfe0a8b339dbda43258a67443183fcc"
    hash2       = "a7ac1561634dc1fa8b18cc98ccf432021ed2e8b16132f60e88757d855dedeb94"

  strings:
    $s1  = "})(),(function f000(){return \"Wb\";})(),(function f000(){return \"Do\";})(),(function f000(){return \"DIa\";})(),(function f000" ascii
    $s2  = "nction f000(){return \"MDb\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"Lp\";})(),(function f000(){retu" ascii
    $s3  = "function f000(){return \"TKp\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"Oh\";})(),(function f000(){re" ascii
    $s4  = "ction f000(){return \"XTn\";})(),(function f000(){return \"Do\";})(),(function f000(){return \"GGn\";})(),(function f000(){retur" ascii
    $s5  = "nction f000(){return \"OUx\";})(),(function f000(){return \"RPt\";})(),(function f000(){return \"Qj\";})(),(function f000(){retu" ascii
    $s6  = "nction f000(){return \"RPt\";})(),(function f000(){return \"Kw\";})(),(function f000(){return \"TKl\";})(),(function f000(){retu" ascii
    $s7  = "DNa\";})(),(function f000(){return \"Iq\";})(),(function f000(){return \"KXg\";})(),(function f000(){return \"QDg\";})(),(functi" ascii
    $s8  = "Pt\";})(),(function f000(){return \"Lp\";})(),(function f000(){return \"Qj\";})(),(function f000(){return \"Zj\";})(),(function " ascii
    $s9  = "on f000(){return \"XTn\";})(),(function f000(){return \"XTn\";})(),(function f000(){return \"GGn\";})(),(function f000(){return " ascii
    $s10 = "0(){return \"RPt\";})(),(function f000(){return \"Yi\";})(),(function f000(){return \"Kw\";})(),(function f000(){return \"Zj\";}" ascii
    $s11 = "){return \"KXg\";})(),(function f000(){return \"Do\";})(),(function f000(){return \"XTn\";})(),(function f000(){return \"Zj\";})" ascii
    $s12 = "Kw\";})(),(function f000(){return \"Qj\";})(),(function f000(){return \"RPt\";})(),(function f000(){return \"XTn\";})(),(functio" ascii
    $s13 = "ion f000(){return \"Qz\";})(),(function f000(){return \"XTn\";})(),(function f000(){return \"Yi\";})(),(function f000(){return " ascii
    $s14 = " f000(){return \"Oe\";})(),(function f000(){return \"MMz\";})(),(function f000(){return \"MKa\";})(),(function f000(){return \"O" ascii
    $s15 = "rn \"Rh\";})(),(function f000(){return \"TRc\";})(),(function f000(){return \"QDg\";})(),(function f000(){return \"Um\";})(),(fu" ascii
    $s16 = "Tn\";})(),(function f000(){return \"Lp\";})(),(function f000(){return \"Kw\";})(),(function f000(){return \"TRc\";})(),(function" ascii
    $s17 = "return \"GGn\";})(),(function f000(){return \"QDg\";})(),(function f000(){return \"Oh\";})(),(function f000(){return \"ZIi\";})(" ascii
    $s18 = "ion f000(){return \"Tn\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"KDh\";})(),(function f000(){return " ascii
    $s19 = "turn \"TKl\";})(),(function f000(){return \"Do\";})(),(function f000(){return \"Lp\";})(),(function f000(){return \"TRc\";})(),(" ascii
    $s20 = "eturn \"GGn\";})(),(function f000(){return \"XTn\";})(),(function f000(){return \"XTn\";})(),(function f000(){return \"Qj\";})()" ascii

  condition:
    (uint16(0) == 0x2f0a and (8 of them)
    ) or (all of them)
}