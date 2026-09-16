rule _20160921_970f1dd445269cda0ba5e6f9fd675983_20160921_a31336f19235_5567 {
  meta:
    description = "datamaliciousorder - from files 20160921_970f1dd445269cda0ba5e6f9fd675983.js, 20160921_a31336f192353e1997fed06b582e1aef.js, 20160921_be923844637026740bc9e5a4aad21ebe.js, 20160922_b9c8ae1e2648708b7b599ba2ac6333c1.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "eb33bb458042e91be0620012d2d05aaafd9742abb0880d1389b5c02b834e9290"
    hash2       = "762774d5263bffcad635355a63715b9cd26c09b53efe134be033e8dff5062b47"
    hash3       = "f50e7368497d3ab714aae3798280c1b53ff9f91f0081f1eafa0b9e23e4928336"
    hash4       = "e2b244eea80e558d4ae468572be8ba3fade8163b0f8751b10ba6ca2263421085"

  strings:
    $s1 = "tion f000(){return \"Kw\";})(),(function f000(){return \"Kw\";})(),(function f000(){return \"KXg\";})(),(function f000(){return " ascii
    $s2 = "turn \"WIj\";})(),(function f000(){return \"KXg\";})(),(function f000(){return \"Do\";})(),(function f000(){return \"Yi\";})(),(" ascii
    $s3 = " \"Qz\";})(),(function f000(){return \"Do\";})(),(function f000(){return \"TRc\";})(),(function f000(){return \"WIj\";})(),(func" ascii
    $s4 = "function f000(){return \"KXg\";})(),(function f000(){return \"Do\";})(),(function f000(){return \"Do\";})(),(function f000(){ret" ascii
    $s5 = "0(){return \"KXg\";})(),(function f000(){return \"Do\";})(),(function f000(){return \"TKl\";})(),(function f000(){return \"Zj\";" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}