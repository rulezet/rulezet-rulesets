rule _20160921_570295874daef65ccf11d909395ae377_20160921_edb059fcf688_82 {
  meta:
    description = "datamaliciousorder - from files 20160921_570295874daef65ccf11d909395ae377.js, 20160921_edb059fcf68869f74200cd1e68a29bc4.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "a5b27b9fc0152c3186c53a02507be373440217ec70f24fc85249bdaebbeb5494"
    hash2       = "9851e93d2e92fdd3882a14c4f00aface7bdc1495b43f7a98040092131f600e38"

  strings:
    $s1  = "f000(){return \"ZGq\";})(),(function f000(){return \"Tn\";})(),(function f000(){return \"MDb\";})(),(function f000(){return \"SE" ascii
    $s2  = " \"OUx\";})(),(function f000(){return \"KXg\";})(),(function f000(){return \"Lp\";})(),(function f000(){return \"KXg\";})(),(fun" ascii
    $s3  = "n f000(){return \"XTn\";})(),(function f000(){return \"MDb\";})(),(function f000(){return \"Oh\";})(),(function f000(){return \"" ascii
    $s4  = "000(){return \"KZr\";})(),(function f000(){return \"MMz\";})(),(function f000(){return \"MKa\";})(),(function f000(){return \"KZ" ascii
    $s5  = "f000(){return \"Rh\";})(),(function f000(){return \"MDb\";})(),(function f000(){return \"Sj\";})(),(function f000(){return \"KDh" ascii
    $s6  = "ion f000(){return \"RPt\";})(),(function f000(){return \"Kw\";})(),(function f000(){return \"Yi\";})(),(function f000(){return " ascii
    $s7  = "on f000(){return \"Oh\";})(),(function f000(){return \"Qa\";})(),(function f000(){return \"NYh\";})(),(function f000(){return \"" ascii
    $s8  = "(function f000(){return \"NYh\";})(),(function f000(){return \"Lp\";})(),(function f000(){return \"MDb\";})(),(function f000(){r" ascii
    $s9  = "urn \"Mc\";})(),(function f000(){return \"Qj\";})(),(function f000(){return \"DIa\";})(),(function f000(){return \"Zj\";})(),(fu" ascii
    $s10 = "eturn \"UEg\";})(),(function f000(){return \"DIa\";})(),(function f000(){return \"MMz\";})(),(function f000(){return \"MKa\";})(" ascii
    $s11 = "n \"OUx\";})(),(function f000(){return \"KXg\";})(),(function f000(){return \"Lp\";})(),(function f000(){return \"Do\";})(),(fun" ascii
    $s12 = "{return \"Rh\";})(),(function f000(){return \"Wy\";})(),(function f000(){return \"QDg\";})(),(function f000(){return \"KDh\";})(" ascii
    $s13 = "unction f000(){return \"KXg\";})(),(function f000(){return \"Lp\";})(),(function f000(){return \"GGn\";})(),(function f000(){ret" ascii
    $s14 = "{return \"Qj\";})(),(function f000(){return \"TRc\";})(),(function f000(){return \"WIj\";})(),(function f000(){return \"Yi\";})(" ascii
    $s15 = "})(),(function f000(){return \"GGn\";})(),(function f000(){return \"QDg\";})(),(function f000(){return \"KXg\";})(),(function f0" ascii
    $s16 = "return \"MBb\";})(),(function f000(){return \"Sq\";})(),(function f000(){return \"Do\";})(),(function f000(){return \"GGn\";})()" ascii
    $s17 = "00(){return \"GGn\";})(),(function f000(){return \"TKl\";})(),(function f000(){return \"Lp\";})(),(function f000(){return \"TKl" ascii
    $s18 = "return \"Qj\";})(),(function f000(){return \"RPt\";})(),(function f000(){return \"Do\";})(),(function f000(){return \"GGn\";})()" ascii
    $s19 = "unction f000(){return \"Kw\";})(),(function f000(){return \"Do\";})(),(function f000(){return \"Qj\";})(),(function f000(){retur" ascii
    $s20 = "urn \"Vj\";})(),(function f000(){return \"Rh\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"MDb\";})(),(f" ascii

  condition:
    (uint16(0) == 0x2f0a and (8 of them)
    ) or (all of them)
}