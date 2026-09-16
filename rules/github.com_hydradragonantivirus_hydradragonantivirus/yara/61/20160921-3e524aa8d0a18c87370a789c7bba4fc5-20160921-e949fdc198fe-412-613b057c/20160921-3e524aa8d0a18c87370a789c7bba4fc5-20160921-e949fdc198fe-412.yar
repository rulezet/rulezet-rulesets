rule _20160921_3e524aa8d0a18c87370a789c7bba4fc5_20160921_e949fdc198fe_412 {
  meta:
    description = "datamaliciousorder - from files 20160921_3e524aa8d0a18c87370a789c7bba4fc5.js, 20160921_e949fdc198fee477717395093f5853e7.js, 20160922_e3f5fbc84de17ad7f507fc3f34b8151f.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "71a83b86275cb43222066a6d27dfb98cdd9fc8283b2b007f9262c38686262b9a"
    hash2       = "4ff56149c45e72e300c579a750f7d49b8e0e723f75bb7a74343267578dd71a4d"
    hash3       = "f0d0a0daceb43d9d9a2f5d51fcc03568ed541f8699acb8b17ce2131c29f14abf"

  strings:
    $s1  = "turn \"Mu\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"Qz\";})(),(function f000(){return \"XTn\";})(),(" ascii
    $s2  = "turn \"Qj\";})(),(function f000(){return \"RPt\";})(),(function f000(){return \"Qz\";})(),(function f000(){return \"Lp\";})(),(f" ascii
    $s3  = " \"WIj\";})(),(function f000(){return \"Yi\";})(),(function f000(){return \"TKl\";})(),(function f000(){return \"GGn\";})(),(fun" ascii
    $s4  = "n \"OUx\";})(),(function f000(){return \"KXg\";})(),(function f000(){return \"KXg\";})(),(function f000(){return \"RPt\";})(),(f" ascii
    $s5  = ")(),(function f000(){return \"TKl\";})(),(function f000(){return \"Qj\";})(),(function f000(){return \"TKl\";})(),(function f000" ascii
    $s6  = " \"XTn\";})(),(function f000(){return \"Lp\";})(),(function f000(){return \"Kw\";})(),(function f000(){return \"Zj\";})(),(funct" ascii
    $s7  = "(){return \"OUx\";})(),(function f000(){return \"RPt\";})(),(function f000(){return \"Qj\";})(),(function f000(){return \"XTn\";" ascii
    $s8  = "ction f000(){return \"Kw\";})(),(function f000(){return \"Qj\";})(),(function f000(){return \"Yi\";})(),(function f000(){return " ascii
    $s9  = "000(){return \"XTn\";})(),(function f000(){return \"XTn\";})(),(function f000(){return \"TKl\";})(),(function f000(){return \"Zj" ascii
    $s10 = "f000(){return \"KXg\";})(),(function f000(){return \"Qz\";})(),(function f000(){return \"DIa\";})(),(function f000(){return \"GG" ascii
    $s11 = "ion f000(){return \"WIj\";})(),(function f000(){return \"KXg\";})(),(function f000(){return \"Do\";})(),(function f000(){return " ascii
    $s12 = "00(){return \"KXg\";})(),(function f000(){return \"TKl\";})(),(function f000(){return \"Do\";})(),(function f000(){return \"GGn" ascii
    $s13 = "eturn \"Mu\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"Qj\";})(),(function f000(){return \"Kw\";})(),(" ascii
    $s14 = "turn \"OUx\";})(),(function f000(){return \"RPt\";})(),(function f000(){return \"Lp\";})(),(function f000(){return \"Qz\";})(),(" ascii
    $s15 = "ction f000(){return \"Kw\";})(),(function f000(){return \"OUx\";})(),(function f000(){return \"RPt\";})(),(function f000(){retur" ascii
    $s16 = "\"Qj\";})(),(function f000(){return \"XTn\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"Mu\";})(),(funct" ascii
    $s17 = ")(),(function f000(){return \"Lp\";})(),(function f000(){return \"Qz\";})(),(function f000(){return \"Zj\";})(),(function f000()" ascii
    $s18 = "(),(function f000(){return \"GGn\";})(),(function f000(){return \"Qj\";})(),(function f000(){return \"Qj\";})(),(function f000()" ascii
    $s19 = "),(function f000(){return \"Qz\";})(),(function f000(){return \"TKl\";})(),(function f000(){return \"KXg\";})(),(function f000()" ascii
    $s20 = "(),(function f000(){return \"Lp\";})(),(function f000(){return \"Do\";})(),(function f000(){return \"KXg\";})(),(function f000()" ascii

  condition:
    (uint16(0) == 0x2f0a and (8 of them)
    ) or (all of them)
}