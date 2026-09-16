rule _20160921_90c3374aed1b4618a92eb40cb007c4b4_20160921_e2594cbf7523_388 {
  meta:
    description = "datamaliciousorder - from files 20160921_90c3374aed1b4618a92eb40cb007c4b4.js, 20160921_e2594cbf75233509eaea515aa1a7a2f1.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "42b3d35e818b5b373b42427cc936c0a099078535d6f37eb5d4dc22b8ac1ee151"
    hash2       = "9bcadd89dbaf0700ab19bcb2d52d99cb9fdc4145fae40ae3eb529de8d9ada04c"

  strings:
    $s1  = ";})(),(function f000(){return \"Kw\";})(),(function f000(){return \"Kw\";})(),(function f000(){return \"Qj\";})(),(function f000" ascii
    $s2  = " f000(){return \"Lp\";})(),(function f000(){return \"XTn\";})(),(function f000(){return \"Lp\";})(),(function f000(){return \"TR" ascii
    $s3  = "\";})(),(function f000(){return \"TKl\";})(),(function f000(){return \"Yi\";})(),(function f000(){return \"GGn\";})(),(function " ascii
    $s4  = "{return \"OUx\";})(),(function f000(){return \"XTn\";})(),(function f000(){return \"XTn\";})(),(function f000(){return \"GGn\";}" ascii
    $s5  = "f000(){return \"WIj\";})(),(function f000(){return \"KXg\";})(),(function f000(){return \"RPt\";})(),(function f000(){return \"Y" ascii
    $s6  = ")(),(function f000(){return \"RPt\";})(),(function f000(){return \"Lp\";})(),(function f000(){return \"GGn\";})(),(function f000" ascii
    $s7  = "j\";})(),(function f000(){return \"RPt\";})(),(function f000(){return \"TKl\";})(),(function f000(){return \"Lp\";})(),(function" ascii
    $s8  = "return \"TKl\";})(),(function f000(){return \"TKl\";})(),(function f000(){return \"XTn\";})(),(function f000(){return \"TRc\";})" ascii
    $s9  = "0(){return \"KXg\";})(),(function f000(){return \"Do\";})(),(function f000(){return \"Kw\";})(),(function f000(){return \"Zj\";}" ascii
    $s10 = "urn \"RPt\";})(),(function f000(){return \"Kw\";})(),(function f000(){return \"Kw\";})(),(function f000(){return \"Zj\";})(),(fu" ascii
    $s11 = "})(),(function f000(){return \"Kw\";})(),(function f000(){return \"XTn\";})(),(function f000(){return \"Qj\";})(),(function f000" ascii
    $s12 = "ion f000(){return \"Kw\";})(),(function f000(){return \"TKl\";})(),(function f000(){return \"Qz\";})(),(function f000(){return " ascii
    $s13 = "00(){return \"GGn\";})(),(function f000(){return \"Lp\";})(),(function f000(){return \"Kw\";})(),(function f000(){return \"RPt\"" ascii
    $s14 = "\"WIj\";})(),(function f000(){return \"KXg\";})(),(function f000(){return \"Do\";})(),(function f000(){return \"XTn\";})(),(func" ascii
    $s15 = "urn \"KXg\";})(),(function f000(){return \"RPt\";})(),(function f000(){return \"RPt\";})(),(function f000(){return \"Zj\";})(),(" ascii
    $s16 = "t\";})(),(function f000(){return \"RPt\";})(),(function f000(){return \"XTn\";})(),(function f000(){return \"Qj\";})(),(function" ascii
    $s17 = "on f000(){return \"KXg\";})(),(function f000(){return \"Lp\";})(),(function f000(){return \"Do\";})(),(function f000(){return \"" ascii
    $s18 = "){return \"Qj\";})(),(function f000(){return \"Lp\";})(),(function f000(){return \"Zj\";})(),(function f000(){return \"MMz\";})(" ascii
    $s19 = " \"Wb\";})(),(function f000(){return \"Do\";})(),(function f000(){return \"WIj\";})(),(function f000(){return \"Oh\";})(),(funct" ascii
    $s20 = "nction f000(){return \"Sv\";})(),(function f000(){return \"Wb\";})(),(function f000(){return \"Do\";})(),(function f000(){return" ascii

  condition:
    (uint16(0) == 0x2f0a and (8 of them)
    ) or (all of them)
}