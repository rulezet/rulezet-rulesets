rule _20160921_5775da34d70f97a2d7aa3296f909af35_20160921_d7492227e681_5221 {
  meta:
    description = "datamaliciousorder - from files 20160921_5775da34d70f97a2d7aa3296f909af35.js, 20160921_d7492227e681b1689bfc5442a91a169e.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "270e1d840937d10ac3eb1fdd04f0fbbbfd31a88a2f316c94c5167a23a2940644"
    hash2       = "63aa129680edf69c72e8f077be5e8562f041fa0b0c7e63a8a9b219c23749b135"

  strings:
    $s1 = "rn \"GGn\";})(),(function f000(){return \"WIj\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"IAa\";})(),(" ascii
    $s2 = "ction f000(){return \"Vu\";})(),(function f000(){return \"Kw\";})(),(function f000(){return \"TKl\";})(),(function f000(){return" ascii
    $s3 = "),(function f000(){return \"RPt\";})(),(function f000(){return \"Vj\";})(),(function f000(){return \"KXg\";})(),(function f000()" ascii
    $s4 = ";})(),(function f000(){return \"XTn\";})(),(function f000(){return \"Vj\";})(),(function f000(){return \"Zj\";})(),(function f00" ascii
    $s5 = "function f000(){return \"Vu\";})(),(function f000(){return \"Kw\";})(),(function f000(){return \"XTn\";})(),(function f000(){ret" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}