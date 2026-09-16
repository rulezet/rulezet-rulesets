rule _20160921_e1835bc92c4604db194bc49df621cade_20160922_0d54e6d044b3_1751 {
  meta:
    description = "datamaliciousorder - from files 20160921_e1835bc92c4604db194bc49df621cade.js, 20160922_0d54e6d044b32b4a5cb86183b32db7ff.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "ca98fbe0aef0208d6ee3df93c692fee8802fb2206893dc56e723bc4af714c0fd"
    hash2       = "bdad94d3c22138ff9e5f70b983cbfbfaee137dc676cd8889f048ac4db0e3e1de"

  strings:
    $s1  = "tion f000(){return \"Tn\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"Uo\";})(),(function f000(){return " ascii
    $s2  = ")(),(function f000(){return \"Mc\";})(),(function f000(){return \"KXg\";})(),(function f000(){return \"GGn\";})(),(function f000" ascii
    $s3  = "),(function f000(){return \"Mc\";})(),(function f000(){return \"Yx\";})(),(function f000(){return \"Wh\";})(),(function f000(){r" ascii
    $s4  = "00(){return \"WIj\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"Br\";})(),(function f000(){return \"YTp" ascii
    $s5  = "\"Br\";})(),(function f000(){return \"Wh\";})(),(function f000(){return \"UEg\";})(),(function f000(){return \"Br\";})(),(functi" ascii
    $s6  = "(){return \"Tn\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"Go\";})(),(function f000(){return \"SGs\";}" ascii
    $s7  = "f000(){return \"Tn\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"Uo\";})(),(function f000(){return \"Nv" ascii
    $s8  = "urn \"GGn\";})(),(function f000(){return \"IAa\";})(),(function f000(){return \"Oh\";})(),(function f000(){return \"YTp\";})(),(" ascii
    $s9  = "nction f000(){return \"PTs\";})(),(function f000(){return \"DYs\";})(),(function f000(){return \"Tn\";})(),(function f000(){retu" ascii
    $s10 = "function f000(){return \"Sq\";})(),(function f000(){return \"TKl\";})(),(function f000(){return \"GGn\";})(),(function f000(){re" ascii
    $s11 = "{return \"TKp\";})(),(function f000(){return \"DYx\";})(),(function f000(){return \"RVb\";})(),(function f000(){return \"Iq\";})" ascii

  condition:
    (uint16(0) == 0x2f0a and (8 of them)
    ) or (all of them)
}