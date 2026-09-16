rule _20160921_68d4a1cff7c2dbc758cf0077184d0d52_20160922_f0d656e55be0_3024 {
  meta:
    description = "datamaliciousorder - from files 20160921_68d4a1cff7c2dbc758cf0077184d0d52.js, 20160922_f0d656e55be0c93b2b5e1f0eda45da9a.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "4d2799f014910856c25b225165971fbe59cf99c8eb1db930d774de46f64d76c2"
    hash2       = "276c24e399a13bf7907294578800d75620fb48bcd34bc84b9d92448375c72d37"

  strings:
    $s1 = "n \"Lp\";})(),(function f000(){return \"TKl\";})(),(function f000(){return \"Qj\";})(),(function f000(){return \"Yi\";})(),(func" ascii
    $s2 = "000(){return \"GGn\";})(),(function f000(){return \"KXg\";})(),(function f000(){return \"KXg\";})(),(function f000(){return \"Yi" ascii
    $s3 = "n \"GGn\";})(),(function f000(){return \"Vu\";})(),(function f000(){return \"Tb\";})(),(function f000(){return \"Sq\";})(),(func" ascii
    $s4 = "0(){return \"TKl\";})(),(function f000(){return \"WIj\";})(),(function f000(){return \"QDg\";})(),(function f000(){return \"Oh\"" ascii
    $s5 = "(){return \"GGn\";})(),(function f000(){return \"KDh\";})(),(function f000(){return \"Yv\";})(),(function f000(){return \"UEg\";" ascii
    $s6 = "DAp\";})(),(function f000(){return \"Wb\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"MDb\";})(),(functi" ascii
    $s7 = "Eo\";})(),(function f000(){return \"ZIi\";})(),(function f000(){return \"BMj\";})(),(function f000(){return \"Lp\";})(),(functio" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}