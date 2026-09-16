rule _20160921_21f60aa0eac9b2e1c271920e1ba030bb_20160921_67c50b9dab5b_251 {
  meta:
    description = "datamaliciousorder - from files 20160921_21f60aa0eac9b2e1c271920e1ba030bb.js, 20160921_67c50b9dab5bb43a7f01552ab820f46c.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "d62e554404acfef03995a5bdd7d29935f7247fd9707d5ea364fac80fddc940f7"
    hash2       = "95b498a0f19ae8b7e9793e4cb9042b95bb6ba62738825d4cc0684c4bbb8a3d9d"

  strings:
    $s1  = "unction f000(){return \"MJq\";})(),(function f000(){return \"TKl\";})(),(function f000(){return \"Ml\";})(),(function f000(){ret" ascii
    $s2  = "return \"GGn\";})(),(function f000(){return \"ZFe\";})(),(function f000(){return \"IPu\";})(),(function f000(){return \"TRc\";})" ascii
    $s3  = "})(),(function f000(){return \"EZu\";})(),(function f000(){return \"Oe\";})(),(function f000(){return \"Tn\";})(),(function f000" ascii
    $s4  = " \"Wy\";})(),(function f000(){return \"OUx\";})(),(function f000(){return \"Yv\";})(),(function f000(){return \"Mc\";})(),(funct" ascii
    $s5  = "),(function f000(){return \"SGs\";})(),(function f000(){return \"Do\";})(),(function f000(){return \"TRc\";})(),(function f000()" ascii
    $s6  = "\"GGn\";})(),(function f000(){return \"PTs\";})(),(function f000(){return \"Nx\";})(),(function f000(){return \"GGn\";})(),(func" ascii
    $s7  = "(function f000(){return \"Km\";})(),(function f000(){return \"Ml\";})(),(function f000(){return \"Tn\";})(),(function f000(){ret" ascii
    $s8  = ";})(),(function f000(){return \"OUx\";})(),(function f000(){return \"ZGq\";})(),(function f000(){return \"Sj\";})(),(function f0" ascii
    $s9  = "tion f000(){return \"Wy\";})(),(function f000(){return \"DYx\";})(),(function f000(){return \"Vj\";})(),(function f000(){return " ascii
    $s10 = ")(),(function f000(){return \"XTn\";})(),(function f000(){return \"OUx\";})(),(function f000(){return \"DNa\";})(),(function f00" ascii
    $s11 = "00(){return \"RPt\";})(),(function f000(){return \"XTn\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"Mu" ascii
    $s12 = "k\";})(),(function f000(){return \"RVb\";})(),(function f000(){return \"TRc\";})(),(function f000(){return \"QDg\";})(),(functio" ascii
    $s13 = "ction f000(){return \"NBs\";})(),(function f000(){return \"TRc\";})(),(function f000(){return \"OUx\";})(),(function f000(){retu" ascii
    $s14 = "){return \"Do\";})(),(function f000(){return \"DIa\";})(),(function f000(){return \"Zj\";})(),(function f000(){return \"KZr\";})" ascii
    $s15 = "000(){return \"Go\";})(),(function f000(){return \"SGs\";})(),(function f000(){return \"Do\";})(),(function f000(){return \"GGn" ascii
    $s16 = "unction f000(){return \"GGn\";})(),(function f000(){return \"Qa\";})(),(function f000(){return \"EZu\";})(),(function f000(){ret" ascii
    $s17 = "n \"GGn\";})(),(function f000(){return \"Uo\";})(),(function f000(){return \"MBb\";})(),(function f000(){return \"Rh\";})(),(fun" ascii
    $s18 = "ion f000(){return \"Zj\";})(),(function f000(){return \"MMz\";})(),(function f000(){return \"MKa\";})(),(function f000(){return " ascii
    $s19 = "nction f000(){return \"TKl\";})(),(function f000(){return \"RPt\";})(),(function f000(){return \"Qj\";})(),(function f000(){retu" ascii
    $s20 = "{return \"PTi\";})(),(function f000(){return \"Lo\";})(),(function f000(){return \"OUx\";})(),(function f000(){return \"Um\";})(" ascii

  condition:
    (uint16(0) == 0x2f0a and (8 of them)
    ) or (all of them)
}