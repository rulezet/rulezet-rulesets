rule _20160921_c05dd34a09358454c56b9c248f1d0304_20160921_c1184914bc80_5673 {
  meta:
    description = "datamaliciousorder - from files 20160921_c05dd34a09358454c56b9c248f1d0304.js, 20160921_c1184914bc801e9725b7f52a13eaa885.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "e330ec83e6ac964ffd679e6589494a6108e1995f570c539dee7b1be30953f8a3"
    hash2       = "b978f77ee1e2384ffdbb55f48f7d8fb0a9b642fc4b2f38d86c68e4f6357d5153"

  strings:
    $s1 = "(function f000(){return \"Mu\";})(),(function f000(){return \"XTn\";})(),(function f000(){return \"KXg\";})(),(function f000(){r" ascii
    $s2 = "ction f000(){return \"RPt\";})(),(function f000(){return \"Yi\";})(),(function f000(){return \"Kw\";})(),(function f000(){return" ascii
    $s3 = "00(){return \"OUx\";})(),(function f000(){return \"KXg\";})(),(function f000(){return \"RPt\";})(),(function f000(){return \"RPt" ascii
    $s4 = "GGn\";})(),(function f000(){return \"RPt\";})(),(function f000(){return \"Qj\";})(),(function f000(){return \"RPt\";})(),(functi" ascii
    $s5 = "tion f000(){return \"RPt\";})(),(function f000(){return \"Qj\";})(),(function f000(){return \"KXg\";})(),(function f000(){return" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}