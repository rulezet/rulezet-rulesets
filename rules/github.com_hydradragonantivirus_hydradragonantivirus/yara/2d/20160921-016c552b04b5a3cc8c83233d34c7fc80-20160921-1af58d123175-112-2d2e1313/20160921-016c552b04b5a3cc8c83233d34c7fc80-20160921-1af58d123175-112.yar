rule _20160921_016c552b04b5a3cc8c83233d34c7fc80_20160921_1af58d123175_112 {
  meta:
    description = "datamaliciousorder - from files 20160921_016c552b04b5a3cc8c83233d34c7fc80.js, 20160921_1af58d1231756b320d04226685b5a131.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "a691692f0982e93fd21c441e8c6d39328f1ea5990ce24999b2df98ee3488f667"
    hash2       = "de59166ad132c3c5ad12a85d2d837c1aec192afb497be23c517c637a08d25171"

  strings:
    $s1  = " f000(){return \"Wy\";})(),(function f000(){return \"Km\";})(),(function f000(){return \"OUx\";})(),(function f000(){return \"Yv" ascii
    $s2  = " f000(){return \"KXg\";})(),(function f000(){return \"ZGq\";})(),(function f000(){return \"ZGq\";})(),(function f000(){return \"" ascii
    $s3  = "n f000(){return \"WIj\";})(),(function f000(){return \"Mu\";})(),(function f000(){return \"Qj\";})(),(function f000(){return \"Z" ascii
    $s4  = "function f000(){return \"GGn\";})(),(function f000(){return \"DYs\";})(),(function f000(){return \"KDh\";})(),(function f000(){r" ascii
    $s5  = "nction f000(){return \"WIj\";})(),(function f000(){return \"KXg\";})(),(function f000(){return \"ZGq\";})(),(function f000(){ret" ascii
    $s6  = "j\";})(),(function f000(){return \"KXg\";})(),(function f000(){return \"ZGq\";})(),(function f000(){return \"Yi\";})(),(function" ascii
    $s7  = ",(function f000(){return \"OUx\";})(),(function f000(){return \"ZGq\";})(),(function f000(){return \"TRc\";})(),(function f000()" ascii
    $s8  = "ction f000(){return \"GGn\";})(),(function f000(){return \"ZGq\";})(),(function f000(){return \"Zj\";})(),(function f000(){retur" ascii
    $s9  = "})(),(function f000(){return \"QDg\";})(),(function f000(){return \"ZGq\";})(),(function f000(){return \"DIa\";})(),(function f0" ascii
    $s10 = "{return \"RPt\";})(),(function f000(){return \"Lp\";})(),(function f000(){return \"ZGq\";})(),(function f000(){return \"XTn\";})" ascii
    $s11 = "0(){return \"MDb\";})(),(function f000(){return \"Vj\";})(),(function f000(){return \"Vj\";})(),(function f000(){return \"Mt\";}" ascii
    $s12 = "){return \"Um\";})(),(function f000(){return \"NBs\";})(),(function f000(){return \"Qz\";})(),(function f000(){return \"TRc\";})" ascii
    $s13 = "turn \"Sq\";})(),(function f000(){return \"Qj\";})(),(function f000(){return \"TRc\";})(),(function f000(){return \"Zj\";})(),(f" ascii
    $s14 = "rn \"SEo\";})(),(function f000(){return \"Tn\";})(),(function f000(){return \"TRc\";})(),(function f000(){return \"TRc\";})(),(f" ascii
    $s15 = " f000(){return \"Tn\";})(),(function f000(){return \"MDb\";})(),(function f000(){return \"KDh\";})(),(function f000(){return \"B" ascii
    $s16 = "tion f000(){return \"XTn\";})(),(function f000(){return \"Yi\";})(),(function f000(){return \"ZGq\";})(),(function f000(){return" ascii
    $s17 = "){return \"Tn\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"Sv\";})(),(function f000(){return \"MBb\";})" ascii
    $s18 = "00(){return \"Tn\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"KDh\";})(),(function f000(){return \"BQb" ascii
    $s19 = "000(){return \"GGn\";})(),(function f000(){return \"MMz\";})(),(function f000(){return \"SGs\";})(),(function f000(){return \"Qj" ascii
    $s20 = "0(){return \"Oe\";})(),(function f000(){return \"Yz\";})(),(function f000(){return \"Br\";})(),(function f000(){return \"GGn\";}" ascii

  condition:
    (uint16(0) == 0x2f0a and (8 of them)
    ) or (all of them)
}