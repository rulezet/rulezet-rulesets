rule _20160921_13c992e435ed245b1977cea0df2db815_20160922_9d6af2734812_4445 {
  meta:
    description = "datamaliciousorder - from files 20160921_13c992e435ed245b1977cea0df2db815.js, 20160922_9d6af27348126e594fbe29c3cf568591.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "289da9cff140ea3b4e35a1aa721314733c057d085ff9e8b5fc3ed7e10f75341b"
    hash2       = "3634189c93f3a76e0a4df72e631f0715b4b71427c157ca5fe116252ca00f1d9b"

  strings:
    $s1 = "00(){return \"GGn\";})(),(function f000(){return \"Wb\";})(),(function f000(){return \"SEo\";})(),(function f000(){return \"Yz\"" ascii
    $s2 = "(),(function f000(){return \"TKl\";})(),(function f000(){return \"Vj\";})(),(function f000(){return \"TKl\";})(),(function f000(" ascii
    $s3 = "Gn\";})(),(function f000(){return \"Qa\";})(),(function f000(){return \"Tn\";})(),(function f000(){return \"Tn\";})(),(function " ascii
    $s4 = "n f000(){return \"Vj\";})(),(function f000(){return \"ZFe\";})(),(function f000(){return \"Zj\";})(),(function f000(){return \"D" ascii
    $s5 = "function f000(){return \"TKp\";})(),(function f000(){return \"Oe\";})(),(function f000(){return \"Nx\";})(),(function f000(){ret" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}