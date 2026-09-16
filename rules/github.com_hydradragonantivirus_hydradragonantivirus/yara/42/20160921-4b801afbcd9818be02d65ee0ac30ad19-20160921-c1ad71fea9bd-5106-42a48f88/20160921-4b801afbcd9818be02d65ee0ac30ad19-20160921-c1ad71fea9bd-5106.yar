rule _20160921_4b801afbcd9818be02d65ee0ac30ad19_20160921_c1ad71fea9bd_5106 {
  meta:
    description = "datamaliciousorder - from files 20160921_4b801afbcd9818be02d65ee0ac30ad19.js, 20160921_c1ad71fea9bd3e371590c0c373f087a1.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "f85dba2504097034fa23d87391ecdaf7fe5f29824616a8d91d353284964bfac1"
    hash2       = "cf0e0decfb5414f48e1bcf494a6c63e6249e9ac1433d4fba6a461b5970957194"

  strings:
    $s1 = "return \"DYs\";})(),(function f000(){return \"Mc\";})(),(function f000(){return \"Vu\";})(),(function f000(){return \"GGn\";})()" ascii
    $s2 = "eturn \"Vj\";})(),(function f000(){return \"Yi\";})(),(function f000(){return \"XTn\";})(),(function f000(){return \"Br\";})(),(" ascii
    $s3 = "(function f000(){return \"Vj\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"Mu\";})(),(function f000(){re" ascii
    $s4 = "on f000(){return \"GGn\";})(),(function f000(){return \"KDh\";})(),(function f000(){return \"Mt\";})(),(function f000(){return " ascii
    $s5 = "ction f000(){return \"Qz\";})(),(function f000(){return \"Vj\";})(),(function f000(){return \"GGn\";})(),(function f000(){return" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}