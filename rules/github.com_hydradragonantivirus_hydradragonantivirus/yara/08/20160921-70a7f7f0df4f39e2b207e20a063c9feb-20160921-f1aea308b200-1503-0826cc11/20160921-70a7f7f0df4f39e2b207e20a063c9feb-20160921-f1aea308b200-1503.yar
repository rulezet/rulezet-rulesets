rule _20160921_70a7f7f0df4f39e2b207e20a063c9feb_20160921_f1aea308b200_1503 {
  meta:
    description = "datamaliciousorder - from files 20160921_70a7f7f0df4f39e2b207e20a063c9feb.js, 20160921_f1aea308b2000a8d722d0f21c756fabf.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "a31a1dde0b2d683e4ae7fa3037209a425605b8e0a49f1607ea1dd02a4eaed267"
    hash2       = "3175e432bce3be89acef4ff7215de666ea47cac857c8c07ff649c1cdd5484103"

  strings:
    $s1  = "00(){return \"Yi\";})(),(function f000(){return \"KXg\";})(),(function f000(){return \"Yi\";})(),(function f000(){return \"DIa\"" ascii
    $s2  = "eturn \"Ot\";})(),(function f000(){return \"UEg\";})(),(function f000(){return \"OUx\";})(),(function f000(){return \"Mu\";})()," ascii
    $s3  = "f000(){return \"TKl\";})(),(function f000(){return \"KXg\";})(),(function f000(){return \"Qj\";})(),(function f000(){return \"XT" ascii
    $s4  = "(function f000(){return \"IPu\";})(),(function f000(){return \"Oe\";})(),(function f000(){return \"OMd\";})(),(function f000(){r" ascii
    $s5  = "\"GGn\";})(),(function f000(){return \"UEg\";})(),(function f000(){return \"DIa\";})(),(function f000(){return \"MMz\";})(),(fun" ascii
    $s6  = "n \"Yz\";})(),(function f000(){return \"Wy\";})(),(function f000(){return \"Km\";})(),(function f000(){return \"OUx\";})(),(func" ascii
    $s7  = "rn \"TRc\";})(),(function f000(){return \"Wh\";})(),(function f000(){return \"Yi\";})(),(function f000(){return \"Do\";})(),(fun" ascii
    $s8  = "Pt\";})(),(function f000(){return \"Ml\";})(),(function f000(){return \"Do\";})(),(function f000(){return \"Zj\";})(),(function " ascii
    $s9  = "f000(){return \"QDg\";})(),(function f000(){return \"Tn\";})(),(function f000(){return \"Yz\";})(),(function f000(){return \"TKp" ascii
    $s10 = " f000(){return \"Wh\";})(),(function f000(){return \"Yi\";})(),(function f000(){return \"Do\";})(),(function f000(){return \"KXg" ascii
    $s11 = "),(function f000(){return \"TKp\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"Go\";})(),(function f000()" ascii
    $s12 = "n f000(){return \"KXg\";})(),(function f000(){return \"Kw\";})(),(function f000(){return \"Do\";})(),(function f000(){return \"Q" ascii
    $s13 = "n \"KXg\";})(),(function f000(){return \"Kw\";})(),(function f000(){return \"RPt\";})(),(function f000(){return \"Do\";})(),(fun" ascii

  condition:
    (uint16(0) == 0x2f0a and (8 of them)
    ) or (all of them)
}