rule _20160921_dff46b67b973e99ec02248f10c2f55c2_20160921_ff1932b6e914_5719 {
  meta:
    description = "datamaliciousorder - from files 20160921_dff46b67b973e99ec02248f10c2f55c2.js, 20160921_ff1932b6e91481dd80ff6251296b57fe.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "2ea0ce06677c6aad57b6618a39beaa56b2c9060cb989c2213eb782aca5d747c2"
    hash2       = "07e5271d8517f89575dc2737fae5e8da89c7f2f25cd40c68e183d826da6b2bf0"

  strings:
    $s1 = "eturn \"GGn\";})(),(function f000(){return \"ZGq\";})(),(function f000(){return \"PTi\";})(),(function f000(){return \"RVb\";})(" ascii
    $s2 = "ion f000(){return \"Sj\";})(),(function f000(){return \"Yz\";})(),(function f000(){return \"TKl\";})(),(function f000(){return " ascii
    $s3 = "n \"Mc\";})(),(function f000(){return \"Wy\";})(),(function f000(){return \"OUx\";})(),(function f000(){return \"ZGq\";})(),(fun" ascii
    $s4 = "MDb\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"EZu\";})(),(function f000(){return \"UEg\";})(),(funct" ascii
    $s5 = "tion f000(){return \"OUx\";})(),(function f000(){return \"DNa\";})(),(function f000(){return \"Sj\";})(),(function f000(){return" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}