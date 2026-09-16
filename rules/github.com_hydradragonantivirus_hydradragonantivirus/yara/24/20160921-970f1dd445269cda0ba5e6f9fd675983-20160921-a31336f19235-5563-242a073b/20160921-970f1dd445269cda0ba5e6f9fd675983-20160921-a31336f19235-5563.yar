rule _20160921_970f1dd445269cda0ba5e6f9fd675983_20160921_a31336f19235_5563 {
  meta:
    description = "datamaliciousorder - from files 20160921_970f1dd445269cda0ba5e6f9fd675983.js, 20160921_a31336f192353e1997fed06b582e1aef.js, 20160921_d47b4a8df4397da0f8d93fe0d9eeb14b.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "eb33bb458042e91be0620012d2d05aaafd9742abb0880d1389b5c02b834e9290"
    hash2       = "762774d5263bffcad635355a63715b9cd26c09b53efe134be033e8dff5062b47"
    hash3       = "78db1c7c22d3adc33c9ba580ac46df953d36c9c15f9c8b211dc68c16595dc18d"

  strings:
    $s1 = "function f000(){return \"Nv\";})(),(function f000(){return \"Vj\";})(),(function f000(){return \"Wy\";})(),(function f000(){retu" ascii
    $s2 = "Aa\";})(),(function f000(){return \"Mc\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"MDb\";})(),(functio" ascii
    $s3 = "\"TKp\";})(),(function f000(){return \"Oe\";})(),(function f000(){return \"ZIi\";})(),(function f000(){return \"GGn\";})(),(func" ascii
    $s4 = "nction f000(){return \"GGn\";})(),(function f000(){return \"Mu\";})(),(function f000(){return \"GGn\";})(),(function f000(){retu" ascii
    $s5 = " \"GGn\";})(),(function f000(){return \"Mu\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"Qa\";})(),(func" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}