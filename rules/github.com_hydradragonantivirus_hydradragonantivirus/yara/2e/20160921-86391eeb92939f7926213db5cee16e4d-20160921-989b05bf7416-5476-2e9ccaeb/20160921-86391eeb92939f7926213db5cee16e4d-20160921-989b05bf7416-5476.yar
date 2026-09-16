rule _20160921_86391eeb92939f7926213db5cee16e4d_20160921_989b05bf7416_5476 {
  meta:
    description = "datamaliciousorder - from files 20160921_86391eeb92939f7926213db5cee16e4d.js, 20160921_989b05bf7416ad8ff0b583666028a2c1.js, 20160922_7e0b1e5964974c7e845016e40a3ad891.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "1238f360c84929f303678fcd3899297cac43bef18dc5a731b7a6272fde7fe4e6"
    hash2       = "c3c2ebe9b3cb36288422e9757d55c015e9201e8ed349ea0a4f3fb5c4042fbfb3"
    hash3       = "de6271315a5e75cb84cc0796ab51f8e68b1d166a3e7393cc14d81a37883277cd"

  strings:
    $s1 = " f000(){return \"TRc\";})(),(function f000(){return \"WIj\";})(),(function f000(){return \"Mu\";})(),(function f000(){return \"X" ascii
    $s2 = "on f000(){return \"WIj\";})(),(function f000(){return \"KXg\";})(),(function f000(){return \"KXg\";})(),(function f000(){return " ascii
    $s3 = "000(){return \"RPt\";})(),(function f000(){return \"RPt\";})(),(function f000(){return \"KXg\";})(),(function f000(){return \"Zj" ascii
    $s4 = "unction f000(){return \"Yi\";})(),(function f000(){return \"OUx\";})(),(function f000(){return \"Qj\";})(),(function f000(){retu" ascii
    $s5 = "urn \"OUx\";})(),(function f000(){return \"KXg\";})(),(function f000(){return \"KXg\";})(),(function f000(){return \"Qz\";})(),(" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}