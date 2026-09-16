rule _20160921_8a6f0879f250e6c15d2c7fa51d20505b_20160921_8dac417cb433_21 {
  meta:
    description = "datamaliciousorder - from files 20160921_8a6f0879f250e6c15d2c7fa51d20505b.js, 20160921_8dac417cb4331fdefcd724e5c4563731.js, 20160921_c6163df7a6dda28826544197fc8ddc4f.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "221e50c91cd5c3d541d89b6c9999d61bacb186433ba85ae94088851587c25391"
    hash2       = "4ab6c9959d63ff05f6b1074253866e4ba4ca6148b9d820313ac79da48c63d90e"
    hash3       = "c0d0b12b3c6fc559a577159775ce104e897b9b5c0422b945c7c097dd53710fe8"

  strings:
    $s1  = "{return \"Vu\";})(),(function f000(){return \"Vj\";})(),(function f000(){return \"IPu\";})(),(function f000(){return \"MDb\";})(" ascii
    $s2  = ",(function f000(){return \"GGn\";})(),(function f000(){return \"KDh\";})(),(function f000(){return \"DNa\";})(),(function f000()" ascii
    $s3  = "n f000(){return \"MDb\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"Vu\";})(),(function f000(){return \"" ascii
    $s4  = "n f000(){return \"RPt\";})(),(function f000(){return \"Do\";})(),(function f000(){return \"Qa\";})(),(function f000(){return \"G" ascii
    $s5  = "rn \"GGn\";})(),(function f000(){return \"SEo\";})(),(function f000(){return \"MBb\";})(),(function f000(){return \"NBs\";})(),(" ascii
    $s6  = "return \"RPt\";})(),(function f000(){return \"XTn\";})(),(function f000(){return \"ZFe\";})(),(function f000(){return \"TRc\";})" ascii
    $s7  = "{return \"Tn\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"Lp\";})(),(function f000(){return \"PTs\";})(" ascii
    $s8  = "ction f000(){return \"Wb\";})(),(function f000(){return \"Do\";})(),(function f000(){return \"OUx\";})(),(function f000(){return" ascii
    $s9  = "unction f000(){return \"EZu\";})(),(function f000(){return \"MJq\";})(),(function f000(){return \"GGn\";})(),(function f000(){re" ascii
    $s10 = "n \"Kw\";})(),(function f000(){return \"Do\";})(),(function f000(){return \"Qz\";})(),(function f000(){return \"Zj\";})(),(funct" ascii
    $s11 = ";})(),(function f000(){return \"Sj\";})(),(function f000(){return \"Iq\";})(),(function f000(){return \"Yi\";})(),(function f000" ascii
    $s12 = "return \"QDg\";})(),(function f000(){return \"RPt\";})(),(function f000(){return \"Yi\";})(),(function f000(){return \"Qa\";})()" ascii
    $s13 = "w\";})(),(function f000(){return \"Qa\";})(),(function f000(){return \"Zj\";})(),(function f000(){return \"MMz\";})(),(function " ascii
    $s14 = "tion f000(){return \"WIj\";})(),(function f000(){return \"ZFe\";})(),(function f000(){return \"Qa\";})(),(function f000(){return" ascii
    $s15 = "{return \"PTs\";})(),(function f000(){return \"NBs\";})(),(function f000(){return \"Yi\";})(),(function f000(){return \"GGn\";})" ascii
    $s16 = "{return \"HJm\";})(),(function f000(){return \"Mc\";})(),(function f000(){return \"Kw\";})(),(function f000(){return \"GGn\";})(" ascii
    $s17 = "rn \"GGn\";})(),(function f000(){return \"PTs\";})(),(function f000(){return \"EZu\";})(),(function f000(){return \"Wy\";})(),(f" ascii
    $s18 = ")(),(function f000(){return \"Qa\";})(),(function f000(){return \"Do\";})(),(function f000(){return \"TKl\";})(),(function f000(" ascii
    $s19 = " f000(){return \"TKp\";})(),(function f000(){return \"OUx\";})(),(function f000(){return \"Vu\";})(),(function f000(){return \"H" ascii
    $s20 = "n \"Br\";})(),(function f000(){return \"Lo\";})(),(function f000(){return \"SGs\";})(),(function f000(){return \"UEg\";})(),(fun" ascii

  condition:
    (uint16(0) == 0x2f0a and (8 of them)
    ) or (all of them)
}