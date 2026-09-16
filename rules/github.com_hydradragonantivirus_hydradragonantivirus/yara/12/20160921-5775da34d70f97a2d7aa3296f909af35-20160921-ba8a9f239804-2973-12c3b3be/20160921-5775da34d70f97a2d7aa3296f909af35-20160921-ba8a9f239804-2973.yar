rule _20160921_5775da34d70f97a2d7aa3296f909af35_20160921_ba8a9f239804_2973 {
  meta:
    description = "datamaliciousorder - from files 20160921_5775da34d70f97a2d7aa3296f909af35.js, 20160921_ba8a9f239804499b5d1d2a06a862c1ca.js, 20160921_ee1327bdf201e62d1f7ae5482cabbd90.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "270e1d840937d10ac3eb1fdd04f0fbbbfd31a88a2f316c94c5167a23a2940644"
    hash2       = "4ab28724a794acc5764f2e51f93d2b91ef9513b43e4cb9b0d10bad2710c2e6d7"
    hash3       = "91500ac726f9d2548dffc99162aeece9863dc7b928106d27a769e6bbf9439f81"

  strings:
    $s1 = "\";})(),(function f000(){return \"IAa\";})(),(function f000(){return \"Oh\";})(),(function f000(){return \"GGn\";})(),(function " ascii
    $s2 = "urn \"Sj\";})(),(function f000(){return \"Oh\";})(),(function f000(){return \"DIa\";})(),(function f000(){return \"Zj\";})(),(fu" ascii
    $s3 = ")(),(function f000(){return \"Tn\";})(),(function f000(){return \"Wy\";})(),(function f000(){return \"PTs\";})(),(function f000(" ascii
    $s4 = "nction f000(){return \"IAa\";})(),(function f000(){return \"Sq\";})(),(function f000(){return \"GGn\";})(),(function f000(){retu" ascii
    $s5 = "return \"WIj\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"IAa\";})(),(function f000(){return \"Sq\";})(" ascii
    $s6 = "000(){return \"Nv\";})(),(function f000(){return \"Sj\";})(),(function f000(){return \"UEg\";})(),(function f000(){return \"GGn" ascii
    $s7 = "ion f000(){return \"Wy\";})(),(function f000(){return \"MMz\";})(),(function f000(){return \"Iq\";})(),(function f000(){return " ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}