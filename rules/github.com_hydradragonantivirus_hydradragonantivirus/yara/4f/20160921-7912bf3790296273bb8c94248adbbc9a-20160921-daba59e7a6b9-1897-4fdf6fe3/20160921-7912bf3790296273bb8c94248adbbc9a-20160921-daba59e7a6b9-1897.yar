rule _20160921_7912bf3790296273bb8c94248adbbc9a_20160921_daba59e7a6b9_1897 {
  meta:
    description = "datamaliciousorder - from files 20160921_7912bf3790296273bb8c94248adbbc9a.js, 20160921_daba59e7a6b9ed6983cd2cbef1eb1597.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "3bf106f8ef0e4b03e869f1cf914513f711eb52824441a1f2740f3faec2821404"
    hash2       = "94c619539e853fdec1958270da7516c52bbcf442ee9ca0569d11e19e70ae29eb"

  strings:
    $s1  = "000(){return \"Yi\";})(),(function f000(){return \"OUx\";})(),(function f000(){return \"Qj\";})(),(function f000(){return \"DNa" ascii
    $s2  = "000(){return \"RPt\";})(),(function f000(){return \"PTs\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"MD" ascii
    $s3  = "ction f000(){return \"PTs\";})(),(function f000(){return \"Qj\";})(),(function f000(){return \"TRc\";})(),(function f000(){retur" ascii
    $s4  = "urn \"TRc\";})(),(function f000(){return \"WIj\";})(),(function f000(){return \"KXg\";})(),(function f000(){return \"PTs\";})()," ascii
    $s5  = "n f000(){return \"OUx\";})(),(function f000(){return \"RPt\";})(),(function f000(){return \"DNa\";})(),(function f000(){return " ascii
    $s6  = "ion f000(){return \"OUx\";})(),(function f000(){return \"RPt\";})(),(function f000(){return \"DNa\";})(),(function f000(){return" ascii
    $s7  = "})(),(function f000(){return \"KXg\";})(),(function f000(){return \"PTs\";})(),(function f000(){return \"XTn\";})(),(function f0" ascii
    $s8  = "\"DNa\";})(),(function f000(){return \"Zj\";})(),(function f000(){return \"Do\";})(),(function f000(){return \"MKa\";})(),(funct" ascii
    $s9  = "\";})(),(function f000(){return \"RPt\";})(),(function f000(){return \"XTn\";})(),(function f000(){return \"PTs\";})(),(function" ascii
    $s10 = "rn \"GGn\";})(),(function f000(){return \"Lp\";})(),(function f000(){return \"HJm\";})(),(function f000(){return \"Mc\";})(),(fu" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}