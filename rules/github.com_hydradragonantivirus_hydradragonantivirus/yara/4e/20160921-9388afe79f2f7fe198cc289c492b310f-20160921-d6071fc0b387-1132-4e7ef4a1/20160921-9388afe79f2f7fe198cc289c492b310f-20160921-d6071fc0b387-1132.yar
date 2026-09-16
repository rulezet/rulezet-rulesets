rule _20160921_9388afe79f2f7fe198cc289c492b310f_20160921_d6071fc0b387_1132 {
  meta:
    description = "datamaliciousorder - from files 20160921_9388afe79f2f7fe198cc289c492b310f.js, 20160921_d6071fc0b387420da4f4d56c9cc4f29c.js, 20160921_e59567324a545ca23bf9e3ba990b6526.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "fd51f1b0a7122eb391698c985377ffff7f055696d2ab09fca71851b63308ba93"
    hash2       = "3582ec61c8d16a4dd7e6b8ba69c238b2abf1b60a1d05ebc8f672103586bdfd47"
    hash3       = "ce1d8f63fc8c7b91e97f36fa89b000d70fc284d08682ca3a91ee6c2a4e6e2c72"

  strings:
    $s1  = "rn \"TKl\";})(),(function f000(){return \"MDb\";})(),(function f000(){return \"Sv\";})(),(function f000(){return \"TKp\";})(),(f" ascii
    $s2  = ",(function f000(){return \"MDb\";})(),(function f000(){return \"Qa\";})(),(function f000(){return \"MJq\";})(),(function f000(){" ascii
    $s3  = "n \"Uo\";})(),(function f000(){return \"ZIi\";})(),(function f000(){return \"Nx\";})(),(function f000(){return \"MDb\";})(),(fun" ascii
    $s4  = ",(function f000(){return \"ZIi\";})(),(function f000(){return \"RVb\";})(),(function f000(){return \"MDb\";})(),(function f000()" ascii
    $s5  = " \"MDb\";})(),(function f000(){return \"HJm\";})(),(function f000(){return \"RLk\";})(),(function f000(){return \"TKp\";})(),(fu" ascii
    $s6  = "00(){return \"Sj\";})(),(function f000(){return \"SEo\";})(),(function f000(){return \"Nx\";})(),(function f000(){return \"GGn\"" ascii
    $s7  = "on f000(){return \"PTi\";})(),(function f000(){return \"DYx\";})(),(function f000(){return \"GGn\";})(),(function f000(){return " ascii
    $s8  = "(){return \"Kw\";})(),(function f000(){return \"TRc\";})(),(function f000(){return \"WIj\";})(),(function f000(){return \"Lp\";}" ascii
    $s9  = ")(),(function f000(){return \"Vu\";})(),(function f000(){return \"Sv\";})(),(function f000(){return \"BMj\";})(),(function f000(" ascii
    $s10 = "nction f000(){return \"Km\";})(),(function f000(){return \"MDb\";})(),(function f000(){return \"DNa\";})(),(function f000(){retu" ascii
    $s11 = "turn \"Iq\";})(),(function f000(){return \"TKl\";})(),(function f000(){return \"MDb\";})(),(function f000(){return \"Vj\";})(),(" ascii
    $s12 = " f000(){return \"UEg\";})(),(function f000(){return \"Lp\";})(),(function f000(){return \"MDb\";})(),(function f000(){return \"N" ascii
    $s13 = "\"DNa\";})(),(function f000(){return \"Wy\";})(),(function f000(){return \"Qz\";})(),(function f000(){return \"GGn\";})(),(funct" ascii
    $s14 = "f000(){return \"Kw\";})(),(function f000(){return \"MDb\";})(),(function f000(){return \"RLk\";})(),(function f000(){return \"BM" ascii
    $s15 = "NYh\";})(),(function f000(){return \"Yi\";})(),(function f000(){return \"MDb\";})(),(function f000(){return \"Sv\";})(),(functio" ascii
    $s16 = "){return \"MBb\";})(),(function f000(){return \"NBs\";})(),(function f000(){return \"MDb\";})(),(function f000(){return \"DYs\";" ascii
    $s17 = "turn \"Sq\";})(),(function f000(){return \"MDb\";})(),(function f000(){return \"PTi\";})(),(function f000(){return \"ZFe\";})()," ascii

  condition:
    (uint16(0) == 0x2f0a and (8 of them)
    ) or (all of them)
}