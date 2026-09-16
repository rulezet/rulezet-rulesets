rule _20160921_18e4d81197d615e3008ec96ea25b7dc4_20160921_297b9b66086a_3442 {
  meta:
    description = "datamaliciousorder - from files 20160921_18e4d81197d615e3008ec96ea25b7dc4.js, 20160921_297b9b66086a46a28327ea94b4a62e58.js, 20160921_40c9b3a004789873984432b531f4fb80.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "4b707313cf8ee2fdf903e5516937a17e48e75059c21a08483659705a96da9670"
    hash2       = "4d719bbec78475fb1d00242f1258699600032a10dd821cc9dfec2254bbe341f7"
    hash3       = "b913ca9b6976b1846b7d36cab5b8fc09147f8eda84e9fde77f0aab4dfe5a2ab3"

  strings:
    $s1 = "Yi\";})(),(function f000(){return \"PTs\";})(),(function f000(){return \"TRc\";})(),(function f000(){return \"WIj\";})(),(functi" ascii
    $s2 = "(function f000(){return \"Kw\";})(),(function f000(){return \"PTs\";})(),(function f000(){return \"Zj\";})(),(function f000(){re" ascii
    $s3 = "unction f000(){return \"PTs\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"MDb\";})(),(function f000(){re" ascii
    $s4 = "),(function f000(){return \"OUx\";})(),(function f000(){return \"PTs\";})(),(function f000(){return \"TRc\";})(),(function f000(" ascii
    $s5 = "{return \"DNa\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"MDb\";})(),(function f000(){return \"GGn\";}" ascii
    $s6 = "\";})(),(function f000(){return \"MMz\";})(),(function f000(){return \"DYs\";})(),(function f000(){return \"Mc\";})(),(function " ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}