rule _20160921_70a7f7f0df4f39e2b207e20a063c9feb_20160921_cebdb99ce2e5_417 {
  meta:
    description = "datamaliciousorder - from files 20160921_70a7f7f0df4f39e2b207e20a063c9feb.js, 20160921_cebdb99ce2e54d24acef5b8ee0096562.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "a31a1dde0b2d683e4ae7fa3037209a425605b8e0a49f1607ea1dd02a4eaed267"
    hash2       = "87071d18d308dc7717dabe03dc0d11efe7ee7231e95d9fca71e480f5f2430f7d"

  strings:
    $s1  = "tion f000(){return \"WIj\";})(),(function f000(){return \"KXg\";})(),(function f000(){return \"KXg\";})(),(function f000(){retur" ascii
    $s2  = "on f000(){return \"Qj\";})(),(function f000(){return \"RPt\";})(),(function f000(){return \"TRc\";})(),(function f000(){return " ascii
    $s3  = "function f000(){return \"NBs\";})(),(function f000(){return \"Yi\";})(),(function f000(){return \"Zj\";})(),(function f000(){ret" ascii
    $s4  = "n f000(){return \"GGn\";})(),(function f000(){return \"RPt\";})(),(function f000(){return \"RPt\";})(),(function f000(){return " ascii
    $s5  = "f000(){return \"Qj\";})(),(function f000(){return \"TKl\";})(),(function f000(){return \"Yi\";})(),(function f000(){return \"TRc" ascii
    $s6  = "){return \"Qj\";})(),(function f000(){return \"TKl\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"MDb\";}" ascii
    $s7  = "){return \"MDb\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"Yi\";})(),(function f000(){return \"Kw\";})" ascii
    $s8  = "ction f000(){return \"Yi\";})(),(function f000(){return \"OUx\";})(),(function f000(){return \"Lp\";})(),(function f000(){return" ascii
    $s9  = ")(),(function f000(){return \"Qj\";})(),(function f000(){return \"Do\";})(),(function f000(){return \"Yi\";})(),(function f000()" ascii
    $s10 = "ion f000(){return \"WIj\";})(),(function f000(){return \"RPt\";})(),(function f000(){return \"Kw\";})(),(function f000(){return " ascii
    $s11 = "turn \"KXg\";})(),(function f000(){return \"RPt\";})(),(function f000(){return \"TKl\";})(),(function f000(){return \"GGn\";})()" ascii
    $s12 = "turn \"TKl\";})(),(function f000(){return \"Yi\";})(),(function f000(){return \"Do\";})(),(function f000(){return \"GGn\";})(),(" ascii
    $s13 = "ction f000(){return \"Qz\";})(),(function f000(){return \"Do\";})(),(function f000(){return \"RPt\";})(),(function f000(){return" ascii
    $s14 = "KXg\";})(),(function f000(){return \"Lp\";})(),(function f000(){return \"TKl\";})(),(function f000(){return \"TRc\";})(),(functi" ascii
    $s15 = "ction f000(){return \"GGn\";})(),(function f000(){return \"Qz\";})(),(function f000(){return \"RPt\";})(),(function f000(){retur" ascii
    $s16 = "{return \"KXg\";})(),(function f000(){return \"Lp\";})(),(function f000(){return \"KXg\";})(),(function f000(){return \"Zj\";})(" ascii
    $s17 = "unction f000(){return \"NBs\";})(),(function f000(){return \"Yi\";})(),(function f000(){return \"GGn\";})(),(function f000(){ret" ascii
    $s18 = " \"RPt\";})(),(function f000(){return \"XTn\";})(),(function f000(){return \"Do\";})(),(function f000(){return \"TRc\";})(),(fun" ascii
    $s19 = "n \"Qj\";})(),(function f000(){return \"KXg\";})(),(function f000(){return \"Do\";})(),(function f000(){return \"TRc\";})(),(fun" ascii
    $s20 = "ction f000(){return \"OUx\";})(),(function f000(){return \"Yi\";})(),(function f000(){return \"Qj\";})(),(function f000(){return" ascii

  condition:
    (uint16(0) == 0x2f0a and (8 of them)
    ) or (all of them)
}