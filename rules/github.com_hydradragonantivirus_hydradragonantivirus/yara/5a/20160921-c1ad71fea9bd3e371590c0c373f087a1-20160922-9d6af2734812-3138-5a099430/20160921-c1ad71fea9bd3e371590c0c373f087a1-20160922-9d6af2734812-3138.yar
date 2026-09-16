rule _20160921_c1ad71fea9bd3e371590c0c373f087a1_20160922_9d6af2734812_3138 {
  meta:
    description = "datamaliciousorder - from files 20160921_c1ad71fea9bd3e371590c0c373f087a1.js, 20160922_9d6af27348126e594fbe29c3cf568591.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "cf0e0decfb5414f48e1bcf494a6c63e6249e9ac1433d4fba6a461b5970957194"
    hash2       = "3634189c93f3a76e0a4df72e631f0715b4b71427c157ca5fe116252ca00f1d9b"

  strings:
    $s1 = "u\";})(),(function f000(){return \"Qz\";})(),(function f000(){return \"Kw\";})(),(function f000(){return \"Qz\";})(),(function f" ascii
    $s2 = "})(),(function f000(){return \"GGn\";})(),(function f000(){return \"RPt\";})(),(function f000(){return \"Kw\";})(),(function f00" ascii
    $s3 = "){return \"Vu\";})(),(function f000(){return \"Vj\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"Ut\";})(" ascii
    $s4 = "ion f000(){return \"GGn\";})(),(function f000(){return \"Vj\";})(),(function f000(){return \"GGn\";})(),(function f000(){return " ascii
    $s5 = "0(){return \"Mu\";})(),(function f000(){return \"KXg\";})(),(function f000(){return \"Vu\";})(),(function f000(){return \"KXg\";" ascii
    $s6 = "unction f000(){return \"RPt\";})(),(function f000(){return \"Vu\";})(),(function f000(){return \"Vu\";})(),(function f000(){retu" ascii
    $s7 = "rn \"GGn\";})(),(function f000(){return \"XTn\";})(),(function f000(){return \"Qz\";})(),(function f000(){return \"RPt\";})(),(f" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}