rule _20160921_be882ab89423f06a9e76ba0cb72775fe_20160922_b22dda4c9fbc_1363 {
  meta:
    description = "datamaliciousorder - from files 20160921_be882ab89423f06a9e76ba0cb72775fe.js, 20160922_b22dda4c9fbc74ba5e251fc3110ada5a.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "fe4f2a5579ff9cbd713377a0d5f78bb0c6c30247b6f455ccdb4014a7c298c978"
    hash2       = "946b208e84c64dbffc7e1cb08a19f629639d795decea5bf8ddd08b34a59e5e59"

  strings:
    $s1  = "\"WIj\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"TKp\";})(),(function f000(){return \"Oe\";})(),(func" ascii
    $s2  = "f000(){return \"Yz\";})(),(function f000(){return \"Tn\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"Sq" ascii
    $s3  = "(){return \"OUx\";})(),(function f000(){return \"Vj\";})(),(function f000(){return \"KDh\";})(),(function f000(){return \"Wy\";}" ascii
    $s4  = "f000(){return \"Yz\";})(),(function f000(){return \"Qj\";})(),(function f000(){return \"Zj\";})(),(function f000(){return \"MMz" ascii
    $s5  = "return \"MDb\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"SEo\";})(),(function f000(){return \"MBb\";})" ascii
    $s6  = "function f000(){return \"UEg\";})(),(function f000(){return \"DYx\";})(),(function f000(){return \"GGn\";})(),(function f000(){r" ascii
    $s7  = "00(){return \"Vj\";})(),(function f000(){return \"Tn\";})(),(function f000(){return \"Tn\";})(),(function f000(){return \"Yz\";}" ascii
    $s8  = "Dg\";})(),(function f000(){return \"Yv\";})(),(function f000(){return \"MJq\";})(),(function f000(){return \"TKl\";})(),(functio" ascii
    $s9  = "unction f000(){return \"ZFe\";})(),(function f000(){return \"KXg\";})(),(function f000(){return \"GGn\";})(),(function f000(){re" ascii
    $s10 = "\";})(),(function f000(){return \"Yv\";})(),(function f000(){return \"ZIi\";})(),(function f000(){return \"GGn\";})(),(function " ascii
    $s11 = "0(){return \"ZIi\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"Vj\";})(),(function f000(){return \"Rh\";" ascii
    $s12 = " \"TKp\";})(),(function f000(){return \"Oe\";})(),(function f000(){return \"ZIi\";})(),(function f000(){return \"GGn\";})(),(fun" ascii
    $s13 = "(){return \"ZFe\";})(),(function f000(){return \"TKl\";})(),(function f000(){return \"RPt\";})(),(function f000(){return \"Qz\";" ascii
    $s14 = "tion f000(){return \"NBs\";})(),(function f000(){return \"TRc\";})(),(function f000(){return \"QDg\";})(),(function f000(){retur" ascii
    $s15 = "})(),(function f000(){return \"Vu\";})(),(function f000(){return \"Um\";})(),(function f000(){return \"RVb\";})(),(function f000" ascii

  condition:
    (uint16(0) == 0x2f0a and (8 of them)
    ) or (all of them)
}