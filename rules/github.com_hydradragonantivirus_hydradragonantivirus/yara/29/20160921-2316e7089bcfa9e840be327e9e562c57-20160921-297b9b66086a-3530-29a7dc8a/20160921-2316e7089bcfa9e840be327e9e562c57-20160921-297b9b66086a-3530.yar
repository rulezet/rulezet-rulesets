rule _20160921_2316e7089bcfa9e840be327e9e562c57_20160921_297b9b66086a_3530 {
  meta:
    description = "datamaliciousorder - from files 20160921_2316e7089bcfa9e840be327e9e562c57.js, 20160921_297b9b66086a46a28327ea94b4a62e58.js, 20160921_40c9b3a004789873984432b531f4fb80.js, 20160921_f232e0ba2dbd66b232f717e912f70cd7.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "11216ce48a9d383f0d3cab03de05ba1550ae25c7b5d18a758666cfdd75159fe2"
    hash2       = "4d719bbec78475fb1d00242f1258699600032a10dd821cc9dfec2254bbe341f7"
    hash3       = "b913ca9b6976b1846b7d36cab5b8fc09147f8eda84e9fde77f0aab4dfe5a2ab3"
    hash4       = "d8231c7ebf650f58f63f7ed6d3017e0ee9895c1dd821750dcc6c78003fc81b2b"

  strings:
    $s1 = "f000(){return \"Qz\";})(),(function f000(){return \"PTs\";})(),(function f000(){return \"Zj\";})(),(function f000(){return \"Do" ascii
    $s2 = "){return \"DNa\";})(),(function f000(){return \"Zj\";})(),(function f000(){return \"Do\";})(),(function f000(){return \"MKa\";})" ascii
    $s3 = ";})(),(function f000(){return \"Do\";})(),(function f000(){return \"MKa\";})(),(function f000(){return \"Uo\";})(),(function f00" ascii
    $s4 = ";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"Nv\";})(),(function f000(){return \"ZGq\";})(),(function f0" ascii
    $s5 = "unction f000(){return \"OUx\";})(),(function f000(){return \"KXg\";})(),(function f000(){return \"PTs\";})(),(function f000(){re" ascii
    $s6 = ")(),(function f000(){return \"QDg\";})(),(function f000(){return \"PTs\";})(),(function f000(){return \"DIa\";})(),(function f00" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}