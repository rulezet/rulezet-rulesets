rule _20160921_0fe6501a0417801a0e1868963016e9be_20160921_f7b964e1d5b6_4378 {
  meta:
    description = "datamaliciousorder - from files 20160921_0fe6501a0417801a0e1868963016e9be.js, 20160921_f7b964e1d5b6c5c4999da8838c5d62ca.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "2926229ccbf6b86ba0ed1aa3ab5b137a43467ffe25d09479a7998c2fdc4b2b30"
    hash2       = "a4c4c13a87b8183a01386c2463dc595a8b36ca94eff8c78305da426f160e6427"

  strings:
    $s1 = ")(),(function f000(){return \"Mu\";})(),(function f000(){return \"Qj\";})(),(function f000(){return \"RPt\";})(),(function f000(" ascii
    $s2 = "0(){return \"Yi\";})(),(function f000(){return \"OUx\";})(),(function f000(){return \"Yv\";})(),(function f000(){return \"Nv\";}" ascii
    $s3 = "rn \"Qz\";})(),(function f000(){return \"Lp\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"MDb\";})(),(fu" ascii
    $s4 = "000(){return \"GGn\";})(),(function f000(){return \"Qj\";})(),(function f000(){return \"Lp\";})(),(function f000(){return \"RPt" ascii
    $s5 = "(),(function f000(){return \"Uo\";})(),(function f000(){return \"Km\";})(),(function f000(){return \"GGn\";})(),(function f000()" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}