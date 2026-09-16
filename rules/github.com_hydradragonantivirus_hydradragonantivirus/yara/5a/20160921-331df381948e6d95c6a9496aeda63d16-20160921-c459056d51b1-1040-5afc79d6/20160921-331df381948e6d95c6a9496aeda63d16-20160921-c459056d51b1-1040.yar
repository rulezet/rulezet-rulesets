rule _20160921_331df381948e6d95c6a9496aeda63d16_20160921_c459056d51b1_1040 {
  meta:
    description = "datamaliciousorder - from files 20160921_331df381948e6d95c6a9496aeda63d16.js, 20160921_c459056d51b1a4ea3176139800021b35.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "74d3e5ca6efd3e26128cb4a5ab3009003c70f505b353304608d74dfd028df0d7"
    hash2       = "2caf9c958877250774bdc190d1120c23a5fe115635a6c2d285aa8d62d171db39"

  strings:
    $s1  = "return \"UOt\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"KXg\";})(),(function f000(){return \"Qa\";})(" ascii
    $s2  = "GGn\";})(),(function f000(){return \"MMz\";})(),(function f000(){return \"MKa\";})(),(function f000(){return \"Sv\";})(),(functi" ascii
    $s3  = "Rh\";})(),(function f000(){return \"Yi\";})(),(function f000(){return \"OUx\";})(),(function f000(){return \"IAa\";})(),(functio" ascii
    $s4  = ")(),(function f000(){return \"Ot\";})(),(function f000(){return \"IAa\";})(),(function f000(){return \"Nv\";})(),(function f000(" ascii
    $s5  = "\"OUx\";})(),(function f000(){return \"IAa\";})(),(function f000(){return \"Nv\";})(),(function f000(){return \"Rh\";})(),(funct" ascii
    $s6  = " f000(){return \"GGn\";})(),(function f000(){return \"Qp\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"I" ascii
    $s7  = "return \"GGn\";})(),(function f000(){return \"Ug\";})(),(function f000(){return \"WIj\";})(),(function f000(){return \"GGn\";})(" ascii
    $s8  = "Aa\";})(),(function f000(){return \"Sq\";})(),(function f000(){return \"Zj\";})(),(function f000(){return \"MMz\";})(),(function" ascii
    $s9  = "eturn \"ZFe\";})(),(function f000(){return \"TKl\";})(),(function f000(){return \"TRc\";})(),(function f000(){return \"WIj\";})(" ascii
    $s10 = "000(){return \"Qa\";})(),(function f000(){return \"TRc\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"Qp" ascii
    $s11 = "f000(){return \"SEo\";})(),(function f000(){return \"PTs\";})(),(function f000(){return \"Qj\";})(),(function f000(){return \"Qa" ascii
    $s12 = "(),(function f000(){return \"EZu\";})(),(function f000(){return \"UEg\";})(),(function f000(){return \"TRc\";})(),(function f000" ascii
    $s13 = "turn \"KXg\";})(),(function f000(){return \"Kw\";})(),(function f000(){return \"TKl\";})(),(function f000(){return \"OMd\";})()," ascii
    $s14 = ")(),(function f000(){return \"OUx\";})(),(function f000(){return \"ZGq\";})(),(function f000(){return \"Mt\";})(),(function f000" ascii
    $s15 = "ion f000(){return \"Zj\";})(),(function f000(){return \"Ot\";})(),(function f000(){return \"MMz\";})(),(function f000(){return " ascii
    $s16 = "n f000(){return \"RPt\";})(),(function f000(){return \"QDg\";})(),(function f000(){return \"IAa\";})(),(function f000(){return " ascii
    $s17 = "n f000(){return \"GGn\";})(),(function f000(){return \"HJm\";})(),(function f000(){return \"Lp\";})(),(function f000(){return \"" ascii
    $s18 = "ion f000(){return \"OUx\";})(),(function f000(){return \"IAa\";})(),(function f000(){return \"Nv\";})(),(function f000(){return " ascii

  condition:
    (uint16(0) == 0x2f0a and (8 of them)
    ) or (all of them)
}