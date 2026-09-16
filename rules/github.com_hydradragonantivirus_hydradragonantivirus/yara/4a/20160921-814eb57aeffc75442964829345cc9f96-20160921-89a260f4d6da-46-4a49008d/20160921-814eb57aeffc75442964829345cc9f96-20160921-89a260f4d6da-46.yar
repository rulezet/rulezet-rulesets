rule _20160921_814eb57aeffc75442964829345cc9f96_20160921_89a260f4d6da_46 {
  meta:
    description = "datamaliciousorder - from files 20160921_814eb57aeffc75442964829345cc9f96.js, 20160921_89a260f4d6da4d97f251f843cf5e94b0.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "2736df4d651a33824aba7abffa7c08414414ffed9f5f27b4b2d81101cfeb7117"
    hash2       = "700f6c802eb024896efe2b22255973b53752a8f129213c9bba2c4f2ebdc53988"

  strings:
    $s1  = "n\";})(),(function f000(){return \"Yv\";})(),(function f000(){return \"Qa\";})(),(function f000(){return \"Rh\";})(),(function f" ascii
    $s2  = "return \"GGn\";})(),(function f000(){return \"RPt\";})(),(function f000(){return \"ZFe\";})(),(function f000(){return \"Zj\";})(" ascii
    $s3  = "rn \"UEg\";})(),(function f000(){return \"OUx\";})(),(function f000(){return \"ZFe\";})(),(function f000(){return \"TRc\";})(),(" ascii
    $s4  = "turn \"Kw\";})(),(function f000(){return \"TRc\";})(),(function f000(){return \"QDg\";})(),(function f000(){return \"MBb\";})()," ascii
    $s5  = "(){return \"PTs\";})(),(function f000(){return \"Tn\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"WIj\";" ascii
    $s6  = " \"RPt\";})(),(function f000(){return \"XTn\";})(),(function f000(){return \"Vu\";})(),(function f000(){return \"Zj\";})(),(func" ascii
    $s7  = "q\";})(),(function f000(){return \"WIj\";})(),(function f000(){return \"DNa\";})(),(function f000(){return \"MMz\";})(),(functio" ascii
    $s8  = "unction f000(){return \"Qz\";})(),(function f000(){return \"ZFe\";})(),(function f000(){return \"RPt\";})(),(function f000(){ret" ascii
    $s9  = "eturn \"Vu\";})(),(function f000(){return \"Yi\";})(),(function f000(){return \"XTn\";})(),(function f000(){return \"TRc\";})()," ascii
    $s10 = "urn \"MMz\";})(),(function f000(){return \"Wy\";})(),(function f000(){return \"KXg\";})(),(function f000(){return \"GGn\";})(),(" ascii
    $s11 = "(function f000(){return \"Qz\";})(),(function f000(){return \"MDb\";})(),(function f000(){return \"PTi\";})(),(function f000(){r" ascii
    $s12 = "\";})(),(function f000(){return \"OUx\";})(),(function f000(){return \"DAp\";})(),(function f000(){return \"EZu\";})(),(function" ascii
    $s13 = "GGn\";})(),(function f000(){return \"PTi\";})(),(function f000(){return \"Tb\";})(),(function f000(){return \"Oe\";})(),(functio" ascii
    $s14 = " \"BMj\";})(),(function f000(){return \"TRc\";})(),(function f000(){return \"QDg\";})(),(function f000(){return \"Sj\";})(),(fun" ascii
    $s15 = "urn \"Br\";})(),(function f000(){return \"Wh\";})(),(function f000(){return \"Nx\";})(),(function f000(){return \"Yz\";})(),(fun" ascii
    $s16 = "(function f000(){return \"BMj\";})(),(function f000(){return \"Zj\";})(),(function f000(){return \"Do\";})(),(function f000(){re" ascii
    $s17 = "Gn\";})(),(function f000(){return \"Nv\";})(),(function f000(){return \"SEo\";})(),(function f000(){return \"RVb\";})(),(functio" ascii
    $s18 = "(){return \"Uo\";})(),(function f000(){return \"SEo\";})(),(function f000(){return \"Oh\";})(),(function f000(){return \"MDb\";}" ascii
    $s19 = "b\";})(),(function f000(){return \"DNa\";})(),(function f000(){return \"Sj\";})(),(function f000(){return \"UEg\";})(),(function" ascii
    $s20 = "e\";})(),(function f000(){return \"WIj\";})(),(function f000(){return \"KDh\";})(),(function f000(){return \"SEo\";})(),(functio" ascii

  condition:
    (uint16(0) == 0x2f0a and (8 of them)
    ) or (all of them)
}