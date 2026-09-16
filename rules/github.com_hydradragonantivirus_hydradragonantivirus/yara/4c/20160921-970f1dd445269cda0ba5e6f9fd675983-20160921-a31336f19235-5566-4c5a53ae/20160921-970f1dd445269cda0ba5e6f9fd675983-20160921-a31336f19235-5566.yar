rule _20160921_970f1dd445269cda0ba5e6f9fd675983_20160921_a31336f19235_5566 {
  meta:
    description = "datamaliciousorder - from files 20160921_970f1dd445269cda0ba5e6f9fd675983.js, 20160921_a31336f192353e1997fed06b582e1aef.js, 20160921_c459056d51b1a4ea3176139800021b35.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "eb33bb458042e91be0620012d2d05aaafd9742abb0880d1389b5c02b834e9290"
    hash2       = "762774d5263bffcad635355a63715b9cd26c09b53efe134be033e8dff5062b47"
    hash3       = "2caf9c958877250774bdc190d1120c23a5fe115635a6c2d285aa8d62d171db39"

  strings:
    $s1 = "f000(){return \"OUx\";})(),(function f000(){return \"ZFe\";})(),(function f000(){return \"TKl\";})(),(function f000(){return \"T" ascii
    $s2 = ")(),(function f000(){return \"Qz\";})(),(function f000(){return \"ZFe\";})(),(function f000(){return \"XTn\";})(),(function f000" ascii
    $s3 = "000(){return \"Lo\";})(),(function f000(){return \"RPt\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"MDb" ascii
    $s4 = "n f000(){return \"ZFe\";})(),(function f000(){return \"RPt\";})(),(function f000(){return \"Zj\";})(),(function f000(){return \"" ascii
    $s5 = "return \"Qa\";})(),(function f000(){return \"Do\";})(),(function f000(){return \"TRc\";})(),(function f000(){return \"WIj\";})()" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}