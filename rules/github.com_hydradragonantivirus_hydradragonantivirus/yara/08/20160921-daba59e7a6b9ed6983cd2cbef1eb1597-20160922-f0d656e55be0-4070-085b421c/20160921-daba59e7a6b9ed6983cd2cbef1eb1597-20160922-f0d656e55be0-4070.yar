rule _20160921_daba59e7a6b9ed6983cd2cbef1eb1597_20160922_f0d656e55be0_4070 {
  meta:
    description = "datamaliciousorder - from files 20160921_daba59e7a6b9ed6983cd2cbef1eb1597.js, 20160922_f0d656e55be0c93b2b5e1f0eda45da9a.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "94c619539e853fdec1958270da7516c52bbcf442ee9ca0569d11e19e70ae29eb"
    hash2       = "276c24e399a13bf7907294578800d75620fb48bcd34bc84b9d92448375c72d37"

  strings:
    $s1 = "ction f000(){return \"UEg\";})(),(function f000(){return \"DYx\";})(),(function f000(){return \"OUx\";})(),(function f000(){retu" ascii
    $s2 = "on f000(){return \"GGn\";})(),(function f000(){return \"Nv\";})(),(function f000(){return \"Mt\";})(),(function f000(){return \"" ascii
    $s3 = ";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"DYs\";})(),(function f000(){return \"Go\";})(),(function f0" ascii
    $s4 = "a\";})(),(function f000(){return \"Go\";})(),(function f000(){return \"MJq\";})(),(function f000(){return \"Qz\";})(),(function " ascii
    $s5 = "tion f000(){return \"Uo\";})(),(function f000(){return \"YTp\";})(),(function f000(){return \"GGn\";})(),(function f000(){return" ascii
    $s6 = "{return \"TKp\";})(),(function f000(){return \"RPt\";})(),(function f000(){return \"DIa\";})(),(function f000(){return \"Zj\";})" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}