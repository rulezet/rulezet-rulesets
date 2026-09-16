rule _20160921_05de6ed1bba9a99cad4c92bf9ce97005_20160921_d7492227e681_1777 {
  meta:
    description = "datamaliciousorder - from files 20160921_05de6ed1bba9a99cad4c92bf9ce97005.js, 20160921_d7492227e681b1689bfc5442a91a169e.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "cc9a1bb338cbe502eae2d8092d1b4369f9be8a107f4db340bf51a1640991e960"
    hash2       = "63aa129680edf69c72e8f077be5e8562f041fa0b0c7e63a8a9b219c23749b135"

  strings:
    $s1  = "(){return \"Sj\";})(),(function f000(){return \"Mc\";})(),(function f000(){return \"Vu\";})(),(function f000(){return \"DIa\";})" ascii
    $s2  = ")(),(function f000(){return \"GGn\";})(),(function f000(){return \"DYs\";})(),(function f000(){return \"Wb\";})(),(function f000" ascii
    $s3  = "tion f000(){return \"Zj\";})(),(function f000(){return \"Ot\";})(),(function f000(){return \"Ot\";})(),(function f000(){return " ascii
    $s4  = "n \"Ot\";})(),(function f000(){return \"DYs\";})(),(function f000(){return \"Wb\";})(),(function f000(){return \"Sq\";})(),(func" ascii
    $s5  = "Wb\";})(),(function f000(){return \"Sq\";})(),(function f000(){return \"KXg\";})(),(function f000(){return \"DIa\";})(),(functio" ascii
    $s6  = "0(){return \"GGn\";})(),(function f000(){return \"RPt\";})(),(function f000(){return \"ZFe\";})(),(function f000(){return \"KXg" ascii
    $s7  = "f000(){return \"Tn\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"DYs\";})(),(function f000(){return \"Wb" ascii
    $s8  = "0(){return \"KXg\";})(),(function f000(){return \"WIj\";})(),(function f000(){return \"Lp\";})(),(function f000(){return \"NBs\"" ascii
    $s9  = "rn \"Wb\";})(),(function f000(){return \"Sq\";})(),(function f000(){return \"KXg\";})(),(function f000(){return \"OUx\";})(),(fu" ascii
    $s10 = " \"Yi\";})(),(function f000(){return \"ZFe\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"Ut\";})(),(func" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}