rule _20160921_66566a9bbc7830091a244fa6674b709b_20160921_9c9fcc818a70_416 {
  meta:
    description = "datamaliciousorder - from files 20160921_66566a9bbc7830091a244fa6674b709b.js, 20160921_9c9fcc818a7064d7449eec45fbad08d9.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "154f7ca38a058d2590f40ec43ada530305244e5c7e86bbedd19aa9c0e1ca02aa"
    hash2       = "988df854145081fce0af79178c78ce75ca8d89b6666ec2e052b7f8de43bb1101"

  strings:
    $s1  = "turn \"Kw\";})(),(function f000(){return \"TKl\";})(),(function f000(){return \"Lp\";})(),(function f000(){return \"Zj\";})(),(f" ascii
    $s2  = "urn \"GGn\";})(),(function f000(){return \"RPt\";})(),(function f000(){return \"Do\";})(),(function f000(){return \"GGn\";})(),(" ascii
    $s3  = "nction f000(){return \"Yi\";})(),(function f000(){return \"Kw\";})(),(function f000(){return \"Yi\";})(),(function f000(){return" ascii
    $s4  = "Xg\";})(),(function f000(){return \"Yi\";})(),(function f000(){return \"Lp\";})(),(function f000(){return \"Zj\";})(),(function " ascii
    $s5  = " f000(){return \"WIj\";})(),(function f000(){return \"Qa\";})(),(function f000(){return \"BQb\";})(),(function f000(){return \"Y" ascii
    $s6  = "n \"OUx\";})(),(function f000(){return \"RPt\";})(),(function f000(){return \"Qj\";})(),(function f000(){return \"TKl\";})(),(fu" ascii
    $s7  = " \"XTn\";})(),(function f000(){return \"KXg\";})(),(function f000(){return \"Do\";})(),(function f000(){return \"TKl\";})(),(fun" ascii
    $s8  = "00(){return \"Kw\";})(),(function f000(){return \"OUx\";})(),(function f000(){return \"Qz\";})(),(function f000(){return \"Lp\";" ascii
    $s9  = "tion f000(){return \"WIj\";})(),(function f000(){return \"Sj\";})(),(function f000(){return \"Iq\";})(),(function f000(){return " ascii
    $s10 = "Ux\";})(),(function f000(){return \"RPt\";})(),(function f000(){return \"Do\";})(),(function f000(){return \"Lp\";})(),(function" ascii
    $s11 = "unction f000(){return \"OUx\";})(),(function f000(){return \"RPt\";})(),(function f000(){return \"Lp\";})(),(function f000(){ret" ascii
    $s12 = "ion f000(){return \"Iq\";})(),(function f000(){return \"Kw\";})(),(function f000(){return \"OUx\";})(),(function f000(){return " ascii
    $s13 = "tion f000(){return \"GGn\";})(),(function f000(){return \"RPt\";})(),(function f000(){return \"TKl\";})(),(function f000(){retur" ascii
    $s14 = "rn \"Lp\";})(),(function f000(){return \"TRc\";})(),(function f000(){return \"WIj\";})(),(function f000(){return \"TKl\";})(),(f" ascii
    $s15 = "\"Qz\";})(),(function f000(){return \"XTn\";})(),(function f000(){return \"Lp\";})(),(function f000(){return \"Kw\";})(),(functi" ascii
    $s16 = " f000(){return \"TKl\";})(),(function f000(){return \"XTn\";})(),(function f000(){return \"Lp\";})(),(function f000(){return \"G" ascii
    $s17 = "function f000(){return \"Ot\";})(),(function f000(){return \"Oh\";})(),(function f000(){return \"Sj\";})(),(function f000(){retu" ascii
    $s18 = " \"Qj\";})(),(function f000(){return \"Kw\";})(),(function f000(){return \"TKl\";})(),(function f000(){return \"Qj\";})(),(funct" ascii
    $s19 = "n\";})(),(function f000(){return \"DYs\";})(),(function f000(){return \"Um\";})(),(function f000(){return \"Mt\";})(),(function " ascii
    $s20 = "tion f000(){return \"Lp\";})(),(function f000(){return \"Qz\";})(),(function f000(){return \"GGn\";})(),(function f000(){return " ascii

  condition:
    (uint16(0) == 0x2f0a and (8 of them)
    ) or (all of them)
}