rule _20160921_08977f7f9e06ddd41f6d4c2067611fb8_20160921_a2977e58d352_335 {
  meta:
    description = "datamaliciousorder - from files 20160921_08977f7f9e06ddd41f6d4c2067611fb8.js, 20160921_a2977e58d35241f07c3f294ca2097899.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "7bfc954e02f30b2a7d9d67f82866d129c9944d4c1b1a2d6e89bf77f6d6c9f997"
    hash2       = "e73f1b219b8d754435de05b984a60d0a49eb426ffb33ef307d21a1f8ee6a7880"

  strings:
    $s1  = " \"GGn\";})(),(function f000(){return \"ZGq\";})(),(function f000(){return \"SEo\";})(),(function f000(){return \"Wy\";})(),(fun" ascii
    $s2  = "eturn \"Sj\";})(),(function f000(){return \"Km\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"WIj\";})()," ascii
    $s3  = "{return \"MBb\";})(),(function f000(){return \"BMj\";})(),(function f000(){return \"MDb\";})(),(function f000(){return \"HJm\";}" ascii
    $s4  = " \"RPt\";})(),(function f000(){return \"TRc\";})(),(function f000(){return \"Zj\";})(),(function f000(){return \"MMz\";})(),(fun" ascii
    $s5  = ")(),(function f000(){return \"Yz\";})(),(function f000(){return \"Qj\";})(),(function f000(){return \"MDb\";})(),(function f000(" ascii
    $s6  = "unction f000(){return \"Tn\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"ZIi\";})(),(function f000(){ret" ascii
    $s7  = "urn \"Do\";})(),(function f000(){return \"OMd\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"Qa\";})(),(f" ascii
    $s8  = "tion f000(){return \"Br\";})(),(function f000(){return \"DYx\";})(),(function f000(){return \"Oe\";})(),(function f000(){return " ascii
    $s9  = "n f000(){return \"GGn\";})(),(function f000(){return \"Vj\";})(),(function f000(){return \"Uo\";})(),(function f000(){return \"K" ascii
    $s10 = "){return \"Km\";})(),(function f000(){return \"Oe\";})(),(function f000(){return \"BQb\";})(),(function f000(){return \"Br\";})(" ascii
    $s11 = " f000(){return \"WIj\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"Br\";})(),(function f000(){return \"X" ascii
    $s12 = "return \"Mc\";})(),(function f000(){return \"KXg\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"WIj\";})(" ascii
    $s13 = "eturn \"QDg\";})(),(function f000(){return \"Vu\";})(),(function f000(){return \"Oe\";})(),(function f000(){return \"GGn\";})()," ascii
    $s14 = "){return \"DYx\";})(),(function f000(){return \"MJq\";})(),(function f000(){return \"Br\";})(),(function f000(){return \"GGn\";}" ascii
    $s15 = "urn \"Tn\";})(),(function f000(){return \"KXg\";})(),(function f000(){return \"MDb\";})(),(function f000(){return \"ZFe\";})(),(" ascii
    $s16 = "0(){return \"Sq\";})(),(function f000(){return \"RPt\";})(),(function f000(){return \"Zj\";})(),(function f000(){return \"MMz\";" ascii
    $s17 = "(){return \"OUx\";})(),(function f000(){return \"PTs\";})(),(function f000(){return \"Yz\";})(),(function f000(){return \"Do\";}" ascii
    $s18 = "{return \"Wy\";})(),(function f000(){return \"Oe\";})(),(function f000(){return \"Um\";})(),(function f000(){return \"Br\";})()," ascii
    $s19 = "ction f000(){return \"Um\";})(),(function f000(){return \"Yz\";})(),(function f000(){return \"Qj\";})(),(function f000(){return " ascii
    $s20 = "(){return \"Oh\";})(),(function f000(){return \"Sq\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"WIj\";}" ascii

  condition:
    (uint16(0) == 0x2f0a and (8 of them)
    ) or (all of them)
}