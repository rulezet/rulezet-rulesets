rule _20160921_2316e7089bcfa9e840be327e9e562c57_20160921_f232e0ba2dbd_19 {
  meta:
    description = "datamaliciousorder - from files 20160921_2316e7089bcfa9e840be327e9e562c57.js, 20160921_f232e0ba2dbd66b232f717e912f70cd7.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "11216ce48a9d383f0d3cab03de05ba1550ae25c7b5d18a758666cfdd75159fe2"
    hash2       = "d8231c7ebf650f58f63f7ed6d3017e0ee9895c1dd821750dcc6c78003fc81b2b"

  strings:
    $s1  = "function f000(){return \"UEg\";})(),(function f000(){return \"OUx\";})(),(function f000(){return \"PTs\";})(),(function f000(){r" ascii
    $s2  = " f000(){return \"RPt\";})(),(function f000(){return \"PTs\";})(),(function f000(){return \"Zj\";})(),(function f000(){return \"G" ascii
    $s3  = "rn \"OUx\";})(),(function f000(){return \"KXg\";})(),(function f000(){return \"DNa\";})(),(function f000(){return \"Yi\";})(),(f" ascii
    $s4  = "\"UEg\";})(),(function f000(){return \"QDg\";})(),(function f000(){return \"ZIi\";})(),(function f000(){return \"IAa\";})(),(fun" ascii
    $s5  = "0(){return \"OUx\";})(),(function f000(){return \"KXg\";})(),(function f000(){return \"KXg\";})(),(function f000(){return \"DNa" ascii
    $s6  = "000(){return \"Nv\";})(),(function f000(){return \"ZGq\";})(),(function f000(){return \"Yz\";})(),(function f000(){return \"TKl" ascii
    $s7  = "(),(function f000(){return \"WIj\";})(),(function f000(){return \"ZGq\";})(),(function f000(){return \"Tb\";})(),(function f000(" ascii
    $s8  = " \"DNa\";})(),(function f000(){return \"TRc\";})(),(function f000(){return \"WIj\";})(),(function f000(){return \"Qj\";})(),(fun" ascii
    $s9  = "RPt\";})(),(function f000(){return \"DNa\";})(),(function f000(){return \"Yi\";})(),(function f000(){return \"TRc\";})(),(functi" ascii
    $s10 = "00(){return \"DNa\";})(),(function f000(){return \"Qj\";})(),(function f000(){return \"Kw\";})(),(function f000(){return \"Zj\";" ascii
    $s11 = " \"BQb\";})(),(function f000(){return \"Qz\";})(),(function f000(){return \"OUx\";})(),(function f000(){return \"HJm\";})(),(fun" ascii
    $s12 = "00(){return \"Ml\";})(),(function f000(){return \"MBb\";})(),(function f000(){return \"Km\";})(),(function f000(){return \"Br\";" ascii
    $s13 = "ion f000(){return \"Qj\";})(),(function f000(){return \"PTs\";})(),(function f000(){return \"Zj\";})(),(function f000(){return " ascii
    $s14 = "Tn\";})(),(function f000(){return \"DNa\";})(),(function f000(){return \"TRc\";})(),(function f000(){return \"WIj\";})(),(functi" ascii
    $s15 = "n \"Wy\";})(),(function f000(){return \"OUx\";})(),(function f000(){return \"Um\";})(),(function f000(){return \"Sq\";})(),(func" ascii
    $s16 = "\"Yi\";})(),(function f000(){return \"MDb\";})(),(function f000(){return \"Vu\";})(),(function f000(){return \"Lp\";})(),(functi" ascii
    $s17 = "\";})(),(function f000(){return \"PTs\";})(),(function f000(){return \"TKl\";})(),(function f000(){return \"Zj\";})(),(function " ascii
    $s18 = "eturn \"GGn\";})(),(function f000(){return \"Vu\";})(),(function f000(){return \"Go\";})(),(function f000(){return \"Rh\";})(),(" ascii
    $s19 = "000(){return \"ZFe\";})(),(function f000(){return \"NYh\";})(),(function f000(){return \"PTs\";})(),(function f000(){return \"GG" ascii
    $s20 = "on f000(){return \"GGn\";})(),(function f000(){return \"DNa\";})(),(function f000(){return \"Qj\";})(),(function f000(){return " ascii

  condition:
    (uint16(0) == 0x2f0a and (8 of them)
    ) or (all of them)
}