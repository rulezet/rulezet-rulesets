rule _20160921_649e29a058d10c3bf9a5a5a06eb3b603_20160921_c05dd34a0935_1882 {
  meta:
    description = "datamaliciousorder - from files 20160921_649e29a058d10c3bf9a5a5a06eb3b603.js, 20160921_c05dd34a09358454c56b9c248f1d0304.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "6565dca0eb9e0e467a96242f29a80c650cc40a8892572ce8c28bfd197ace7fd0"
    hash2       = "e330ec83e6ac964ffd679e6589494a6108e1995f570c539dee7b1be30953f8a3"

  strings:
    $s1  = "\"GGn\";})(),(function f000(){return \"KXg\";})(),(function f000(){return \"TKl\";})(),(function f000(){return \"KXg\";})(),(fun" ascii
    $s2  = "0(){return \"Oh\";})(),(function f000(){return \"BMj\";})(),(function f000(){return \"DIa\";})(),(function f000(){return \"Zj\";" ascii
    $s3  = "n f000(){return \"GGn\";})(),(function f000(){return \"QDg\";})(),(function f000(){return \"Oh\";})(),(function f000(){return \"" ascii
    $s4  = "Ka\";})(),(function f000(){return \"Ot\";})(),(function f000(){return \"Ot\";})(),(function f000(){return \"Yv\";})(),(function " ascii
    $s5  = "(),(function f000(){return \"NBs\";})(),(function f000(){return \"Yi\";})(),(function f000(){return \"GGn\";})(),(function f000(" ascii
    $s6  = "unction f000(){return \"Kw\";})(),(function f000(){return \"OUx\";})(),(function f000(){return \"TKl\";})(),(function f000(){ret" ascii
    $s7  = "{return \"Mu\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"Kw\";})(),(function f000(){return \"Qj\";})()" ascii
    $s8  = "f000(){return \"RPt\";})(),(function f000(){return \"KXg\";})(),(function f000(){return \"RPt\";})(),(function f000(){return \"Q" ascii
    $s9  = "n\";})(),(function f000(){return \"RPt\";})(),(function f000(){return \"KXg\";})(),(function f000(){return \"Lp\";})(),(function" ascii
    $s10 = "Ij\";})(),(function f000(){return \"RPt\";})(),(function f000(){return \"TKl\";})(),(function f000(){return \"TKl\";})(),(functi" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}