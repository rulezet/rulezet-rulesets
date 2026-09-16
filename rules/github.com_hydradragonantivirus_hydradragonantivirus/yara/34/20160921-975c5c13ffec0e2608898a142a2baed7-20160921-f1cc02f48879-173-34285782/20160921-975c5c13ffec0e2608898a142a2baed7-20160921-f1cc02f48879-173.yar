rule _20160921_975c5c13ffec0e2608898a142a2baed7_20160921_f1cc02f48879_173 {
  meta:
    description = "datamaliciousorder - from files 20160921_975c5c13ffec0e2608898a142a2baed7.js, 20160921_f1cc02f488792b7161849f8d15549315.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "4635f6ab0f307c878451c2e13b93f8c364364fd9dbd9b0a493d7990bc3eb3c17"
    hash2       = "a4438fd9b6e1eb385945338a0e8eaf272adfda2172cb3659bc36af2d1cc76ce5"

  strings:
    $s1  = "tion f000(){return \"PTi\";})(),(function f000(){return \"Lo\";})(),(function f000(){return \"OUx\";})(),(function f000(){return" ascii
    $s2  = "n \"Do\";})(),(function f000(){return \"TRc\";})(),(function f000(){return \"WIj\";})(),(function f000(){return \"Do\";})(),(fun" ascii
    $s3  = "MDb\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"ZGq\";})(),(function f000(){return \"NBs\";})(),(funct" ascii
    $s4  = "f000(){return \"GGn\";})(),(function f000(){return \"Br\";})(),(function f000(){return \"SGs\";})(),(function f000(){return \"TK" ascii
    $s5  = "),(function f000(){return \"Do\";})(),(function f000(){return \"OMd\";})(),(function f000(){return \"GGn\";})(),(function f000()" ascii
    $s6  = " \"Br\";})(),(function f000(){return \"Nv\";})(),(function f000(){return \"Go\";})(),(function f000(){return \"Br\";})(),(functi" ascii
    $s7  = "0(){return \"MDb\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"Nv\";})(),(function f000(){return \"SGs\"" ascii
    $s8  = "0(){return \"GGn\";})(),(function f000(){return \"ZIi\";})(),(function f000(){return \"PTs\";})(),(function f000(){return \"Wy\"" ascii
    $s9  = "urn \"Tb\";})(),(function f000(){return \"PTs\";})(),(function f000(){return \"SGs\";})(),(function f000(){return \"Kw\";})(),(f" ascii
    $s10 = "){return \"DYs\";})(),(function f000(){return \"Tn\";})(),(function f000(){return \"Oe\";})(),(function f000(){return \"Br\";})(" ascii
    $s11 = " f000(){return \"Go\";})(),(function f000(){return \"SGs\";})(),(function f000(){return \"MDb\";})(),(function f000(){return \"U" ascii
    $s12 = "rn \"Tn\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"HJm\";})(),(function f000(){return \"IAa\";})(),(f" ascii
    $s13 = "ction f000(){return \"GGn\";})(),(function f000(){return \"Qj\";})(),(function f000(){return \"XTn\";})(),(function f000(){retur" ascii
    $s14 = ",(function f000(){return \"MBb\";})(),(function f000(){return \"BQb\";})(),(function f000(){return \"Zj\";})(),(function f000(){" ascii
    $s15 = "ZGq\";})(),(function f000(){return \"Sq\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"WIj\";})(),(functi" ascii
    $s16 = "n f000(){return \"Br\";})(),(function f000(){return \"Mc\";})(),(function f000(){return \"SGs\";})(),(function f000(){return \"B" ascii
    $s17 = "\";})(),(function f000(){return \"Br\";})(),(function f000(){return \"Wh\";})(),(function f000(){return \"Lo\";})(),(function f0" ascii
    $s18 = "(){return \"QDg\";})(),(function f000(){return \"IAa\";})(),(function f000(){return \"ZGq\";})(),(function f000(){return \"Wy\";" ascii
    $s19 = "(),(function f000(){return \"GGn\";})(),(function f000(){return \"RLk\";})(),(function f000(){return \"MJq\";})(),(function f000" ascii
    $s20 = "\"DAp\";})(),(function f000(){return \"Nx\";})(),(function f000(){return \"TKl\";})(),(function f000(){return \"GGn\";})(),(func" ascii

  condition:
    (uint16(0) == 0x2f0a and (8 of them)
    ) or (all of them)
}