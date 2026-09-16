rule _20160921_702e8529103b960a902ddb030da0de45_20160921_8843826fc0ae_586 {
  meta:
    description = "datamaliciousorder - from files 20160921_702e8529103b960a902ddb030da0de45.js, 20160921_8843826fc0ae466921b7811b54d8314e.js, 20160921_9bf90f0e5e3e4249facf6ba81df47434.js, 20160922_37d3775ea966a92be28550dbc5135955.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "cf8ba9fdbe4ef225cb892f7294538710b1dd7e8bc4e280897680c51e03816d1c"
    hash2       = "78595fd8fc9b77e9ad7cb382c7d0ec855211116626b883d04155604a9a99eab3"
    hash3       = "7675c3fc0c8c80a2bcfa4fe026386a71ba43352c33e15df8f556bb3e96e97ab5"
    hash4       = "f282b6549f474db716715761c7740ac0669f87438abd864f0e5afe9b148cb29b"

  strings:
    $s1  = "n f000(){return \"Wb\";})(),(function f000(){return \"Do\";})(),(function f000(){return \"OUx\";})(),(function f000(){return \"Q" ascii
    $s2  = ",(function f000(){return \"Um\";})(),(function f000(){return \"SGs\";})(),(function f000(){return \"GGn\";})(),(function f000(){" ascii
    $s3  = "n f000(){return \"KDh\";})(),(function f000(){return \"Km\";})(),(function f000(){return \"RPt\";})(),(function f000(){return \"" ascii
    $s4  = "ion f000(){return \"MDb\";})(),(function f000(){return \"ZGq\";})(),(function f000(){return \"UEg\";})(),(function f000(){return" ascii
    $s5  = "){return \"GGn\";})(),(function f000(){return \"SEo\";})(),(function f000(){return \"Km\";})(),(function f000(){return \"GGn\";}" ascii
    $s6  = "n\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"Nv\";})(),(function f000(){return \"ZFe\";})(),(function" ascii
    $s7  = " \"SGs\";})(),(function f000(){return \"DIa\";})(),(function f000(){return \"Zj\";})(),(function f000(){return \"MMz\";})(),(fun" ascii
    $s8  = ")(),(function f000(){return \"OMd\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"RPt\";})(),(function f00" ascii
    $s9  = "turn \"Sq\";})(),(function f000(){return \"Yz\";})(),(function f000(){return \"Br\";})(),(function f000(){return \"GGn\";})(),(f" ascii
    $s10 = ",(function f000(){return \"MDb\";})(),(function f000(){return \"Oh\";})(),(function f000(){return \"Mt\";})(),(function f000(){r" ascii
    $s11 = "Db\";})(),(function f000(){return \"Vu\";})(),(function f000(){return \"Iq\";})(),(function f000(){return \"Yi\";})(),(function " ascii
    $s12 = "DYs\";})(),(function f000(){return \"Mc\";})(),(function f000(){return \"Qj\";})(),(function f000(){return \"GGn\";})(),(functio" ascii
    $s13 = "000(){return \"Sq\";})(),(function f000(){return \"TKl\";})(),(function f000(){return \"WIj\";})(),(function f000(){return \"QDg" ascii
    $s14 = "turn \"TKl\";})(),(function f000(){return \"Qz\";})(),(function f000(){return \"Do\";})(),(function f000(){return \"Kw\";})(),(f" ascii
    $s15 = "000(){return \"GGn\";})(),(function f000(){return \"PTs\";})(),(function f000(){return \"MJq\";})(),(function f000(){return \"WI" ascii
    $s16 = "\"Lp\";})(),(function f000(){return \"Yi\";})(),(function f000(){return \"XTn\";})(),(function f000(){return \"Br\";})(),(functi" ascii
    $s17 = "unction f000(){return \"RPt\";})(),(function f000(){return \"RPt\";})(),(function f000(){return \"Br\";})(),(function f000(){ret" ascii
    $s18 = "eturn \"Do\";})(),(function f000(){return \"MDb\";})(),(function f000(){return \"Vj\";})(),(function f000(){return \"Iq\";})(),(" ascii
    $s19 = "urn \"Tn\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"Vu\";})(),(function f000(){return \"Tb\";})(),(fu" ascii
    $s20 = "),(function f000(){return \"Yi\";})(),(function f000(){return \"Lp\";})(),(function f000(){return \"Yi\";})(),(function f000(){r" ascii

  condition:
    (uint16(0) == 0x2f0a and (8 of them)
    ) or (all of them)
}