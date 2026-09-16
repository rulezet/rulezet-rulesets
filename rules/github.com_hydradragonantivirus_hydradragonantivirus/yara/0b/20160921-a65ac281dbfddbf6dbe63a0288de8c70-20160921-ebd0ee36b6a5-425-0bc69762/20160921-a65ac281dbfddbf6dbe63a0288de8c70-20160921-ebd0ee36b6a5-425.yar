rule _20160921_a65ac281dbfddbf6dbe63a0288de8c70_20160921_ebd0ee36b6a5_425 {
  meta:
    description = "datamaliciousorder - from files 20160921_a65ac281dbfddbf6dbe63a0288de8c70.js, 20160921_ebd0ee36b6a55e4cbf431d8fa9a2aea3.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "5498e9d2bd6a9339a0b2314825151361bd8dd59a555d034973bbcac8e2cb195a"
    hash2       = "f2f666db493211ee6edb824e429f601fccdbf25cd3cc08bc16ad31fdf23c4636"

  strings:
    $s1  = "unction f000(){return \"Lp\";})(),(function f000(){return \"Do\";})(),(function f000(){return \"KXg\";})(),(function f000(){retu" ascii
    $s2  = " \"Qz\";})(),(function f000(){return \"Lp\";})(),(function f000(){return \"Lp\";})(),(function f000(){return \"GGn\";})(),(funct" ascii
    $s3  = " \"Mu\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"Qj\";})(),(function f000(){return \"Kw\";})(),(funct" ascii
    $s4  = "urn \"Lp\";})(),(function f000(){return \"Qj\";})(),(function f000(){return \"KXg\";})(),(function f000(){return \"Zj\";})(),(fu" ascii
    $s5  = "ction f000(){return \"KXg\";})(),(function f000(){return \"Yi\";})(),(function f000(){return \"Lp\";})(),(function f000(){return" ascii
    $s6  = "eturn \"TRc\";})(),(function f000(){return \"WIj\";})(),(function f000(){return \"TKl\";})(),(function f000(){return \"Qj\";})()" ascii
    $s7  = "00(){return \"Qz\";})(),(function f000(){return \"Lp\";})(),(function f000(){return \"Qj\";})(),(function f000(){return \"GGn\";" ascii
    $s8  = "f000(){return \"Lp\";})(),(function f000(){return \"KXg\";})(),(function f000(){return \"Kw\";})(),(function f000(){return \"Qj" ascii
    $s9  = "on f000(){return \"Kw\";})(),(function f000(){return \"Yi\";})(),(function f000(){return \"Do\";})(),(function f000(){return \"T" ascii
    $s10 = "000(){return \"KXg\";})(),(function f000(){return \"RPt\";})(),(function f000(){return \"Kw\";})(),(function f000(){return \"TRc" ascii
    $s11 = "(function f000(){return \"WIj\";})(),(function f000(){return \"Lp\";})(),(function f000(){return \"KXg\";})(),(function f000(){r" ascii
    $s12 = "ction f000(){return \"Qz\";})(),(function f000(){return \"Qj\";})(),(function f000(){return \"Zj\";})(),(function f000(){return " ascii
    $s13 = "ion f000(){return \"KXg\";})(),(function f000(){return \"Kw\";})(),(function f000(){return \"Yi\";})(),(function f000(){return " ascii
    $s14 = "return \"KXg\";})(),(function f000(){return \"TKl\";})(),(function f000(){return \"Do\";})(),(function f000(){return \"GGn\";})(" ascii
    $s15 = "turn \"GGn\";})(),(function f000(){return \"Qj\";})(),(function f000(){return \"TKl\";})(),(function f000(){return \"Qj\";})(),(" ascii
    $s16 = "\";})(),(function f000(){return \"Kw\";})(),(function f000(){return \"TKl\";})(),(function f000(){return \"TKl\";})(),(function " ascii
    $s17 = "unction f000(){return \"GGn\";})(),(function f000(){return \"Qj\";})(),(function f000(){return \"Qj\";})(),(function f000(){retu" ascii
    $s18 = "unction f000(){return \"GGn\";})(),(function f000(){return \"Lp\";})(),(function f000(){return \"RPt\";})(),(function f000(){ret" ascii
    $s19 = "unction f000(){return \"Lp\";})(),(function f000(){return \"Yi\";})(),(function f000(){return \"GGn\";})(),(function f000(){retu" ascii
    $s20 = "})(),(function f000(){return \"RPt\";})(),(function f000(){return \"Lp\";})(),(function f000(){return \"XTn\";})(),(function f00" ascii

  condition:
    (uint16(0) == 0x2f0a and (8 of them)
    ) or (all of them)
}