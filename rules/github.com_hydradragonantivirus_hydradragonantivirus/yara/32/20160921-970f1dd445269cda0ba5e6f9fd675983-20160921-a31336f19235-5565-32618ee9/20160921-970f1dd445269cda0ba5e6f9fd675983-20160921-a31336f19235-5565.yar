rule _20160921_970f1dd445269cda0ba5e6f9fd675983_20160921_a31336f19235_5565 {
  meta:
    description = "datamaliciousorder - from files 20160921_970f1dd445269cda0ba5e6f9fd675983.js, 20160921_a31336f192353e1997fed06b582e1aef.js, 20160922_99c635a67f8963210ce99c7a8cf9cd6c.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "eb33bb458042e91be0620012d2d05aaafd9742abb0880d1389b5c02b834e9290"
    hash2       = "762774d5263bffcad635355a63715b9cd26c09b53efe134be033e8dff5062b47"
    hash3       = "c5b5cdc3be24f457939814321b7f3397a8f4d2370b1e57cdae1f3f10537e562c"

  strings:
    $s1 = "(function f000(){return \"GGn\";})(),(function f000(){return \"KDh\";})(),(function f000(){return \"Uo\";})(),(function f000(){r" ascii
    $s2 = "})(),(function f000(){return \"GGn\";})(),(function f000(){return \"ZFe\";})(),(function f000(){return \"KXg\";})(),(function f0" ascii
    $s3 = "0(){return \"NYh\";})(),(function f000(){return \"Qa\";})(),(function f000(){return \"OMd\";})(),(function f000(){return \"GGn\"" ascii
    $s4 = "00(){return \"Lp\";})(),(function f000(){return \"DYx\";})(),(function f000(){return \"WIj\";})(),(function f000(){return \"Go\"" ascii
    $s5 = " f000(){return \"BQb\";})(),(function f000(){return \"Qz\";})(),(function f000(){return \"OUx\";})(),(function f000(){return \"R" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}