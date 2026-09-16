rule _20160921_2316e7089bcfa9e840be327e9e562c57_20160921_9c9fcc818a70_3532 {
  meta:
    description = "datamaliciousorder - from files 20160921_2316e7089bcfa9e840be327e9e562c57.js, 20160921_9c9fcc818a7064d7449eec45fbad08d9.js, 20160921_e1bc53e337e27af13c4323bd3332a33c.js, 20160921_f232e0ba2dbd66b232f717e912f70cd7.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "11216ce48a9d383f0d3cab03de05ba1550ae25c7b5d18a758666cfdd75159fe2"
    hash2       = "988df854145081fce0af79178c78ce75ca8d89b6666ec2e052b7f8de43bb1101"
    hash3       = "7561e1bb060dd07ca80dc6e0b089a853d0081d60c7843d73299f7dabb92efaea"
    hash4       = "d8231c7ebf650f58f63f7ed6d3017e0ee9895c1dd821750dcc6c78003fc81b2b"

  strings:
    $s1 = "),(function f000(){return \"Wy\";})(),(function f000(){return \"Yz\";})(),(function f000(){return \"Wy\";})(),(function f000(){r" ascii
    $s2 = "\"Oe\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"UOt\";})(),(function f000(){return \"GGn\";})(),(func" ascii
    $s3 = "return \"TKl\";})(),(function f000(){return \"Ml\";})(),(function f000(){return \"Tn\";})(),(function f000(){return \"Oe\";})()," ascii
    $s4 = "0(){return \"Ot\";})(),(function f000(){return \"EZu\";})(),(function f000(){return \"Km\";})(),(function f000(){return \"Iq\";}" ascii
    $s5 = "ction f000(){return \"BQb\";})(),(function f000(){return \"Oe\";})(),(function f000(){return \"GGn\";})(),(function f000(){retur" ascii
    $s6 = "n f000(){return \"Yz\";})(),(function f000(){return \"YTp\";})(),(function f000(){return \"Mt\";})(),(function f000(){return \"U" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}