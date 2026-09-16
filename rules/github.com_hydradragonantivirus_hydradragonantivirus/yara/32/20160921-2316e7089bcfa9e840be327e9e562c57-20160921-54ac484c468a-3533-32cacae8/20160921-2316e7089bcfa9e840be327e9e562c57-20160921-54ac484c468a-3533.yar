rule _20160921_2316e7089bcfa9e840be327e9e562c57_20160921_54ac484c468a_3533 {
  meta:
    description = "datamaliciousorder - from files 20160921_2316e7089bcfa9e840be327e9e562c57.js, 20160921_54ac484c468ac2ca7fe6c7210ca717bb.js, 20160921_f232e0ba2dbd66b232f717e912f70cd7.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "11216ce48a9d383f0d3cab03de05ba1550ae25c7b5d18a758666cfdd75159fe2"
    hash2       = "5b883334540a4216b3582d1f2fa0a27f21b9c64a87944c8e58d9fab0f609eef3"
    hash3       = "d8231c7ebf650f58f63f7ed6d3017e0ee9895c1dd821750dcc6c78003fc81b2b"

  strings:
    $s1 = " f000(){return \"Yv\";})(),(function f000(){return \"Sq\";})(),(function f000(){return \"KXg\";})(),(function f000(){return \"Zj" ascii
    $s2 = "})(),(function f000(){return \"TKp\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"Um\";})(),(function f00" ascii
    $s3 = "turn \"Go\";})(),(function f000(){return \"RVb\";})(),(function f000(){return \"QDg\";})(),(function f000(){return \"Vj\";})(),(" ascii
    $s4 = "(){return \"GGn\";})(),(function f000(){return \"HJm\";})(),(function f000(){return \"Sq\";})(),(function f000(){return \"Qj\";}" ascii
    $s5 = ";})(),(function f000(){return \"SGs\";})(),(function f000(){return \"Qj\";})(),(function f000(){return \"GGn\";})(),(function f0" ascii
    $s6 = "n \"NBs\";})(),(function f000(){return \"Yi\";})(),(function f000(){return \"TRc\";})(),(function f000(){return \"Zj\";})(),(fun" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}