rule _20160921_5ac6ab74e4b06b9e82f957e9e7bf6669_20160921_649e29a058d1_5243 {
  meta:
    description = "datamaliciousorder - from files 20160921_5ac6ab74e4b06b9e82f957e9e7bf6669.js, 20160921_649e29a058d10c3bf9a5a5a06eb3b603.js, 20160921_ccabe4fce99c1ebb627aa374a501f33c.js, 20160921_d4f0c091f748680e400a49909c223265.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "50225d12c51a2decb97015971f8ce72487a24a69e64ec1d12fd7f720f2320cf3"
    hash2       = "6565dca0eb9e0e467a96242f29a80c650cc40a8892572ce8c28bfd197ace7fd0"
    hash3       = "449fe576ee25f77acba5442d771e770819941d7dbf354b5123ca5211ef743189"
    hash4       = "1bfdf43dd38b68a1577a28fa30f6ebe7fbbcc8d9fe32db4ebe1b162eaac6ba98"

  strings:
    $s1 = "ion f000(){return \"Qj\";})(),(function f000(){return \"Lp\";})(),(function f000(){return \"XTn\";})(),(function f000(){return " ascii
    $s2 = "0(){return \"Yi\";})(),(function f000(){return \"OUx\";})(),(function f000(){return \"Yi\";})(),(function f000(){return \"Yi\";}" ascii
    $s3 = "WIj\";})(),(function f000(){return \"RPt\";})(),(function f000(){return \"Qj\";})(),(function f000(){return \"Qj\";})(),(functio" ascii
    $s4 = "ction f000(){return \"TKl\";})(),(function f000(){return \"TKl\";})(),(function f000(){return \"XTn\";})(),(function f000(){retu" ascii
    $s5 = "ction f000(){return \"Qj\";})(),(function f000(){return \"XTn\";})(),(function f000(){return \"GGn\";})(),(function f000(){retur" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}