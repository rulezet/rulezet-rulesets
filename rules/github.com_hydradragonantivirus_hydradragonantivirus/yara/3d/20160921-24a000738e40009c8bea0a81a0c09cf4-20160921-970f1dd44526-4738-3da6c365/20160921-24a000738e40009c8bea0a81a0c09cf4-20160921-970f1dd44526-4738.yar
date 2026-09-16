rule _20160921_24a000738e40009c8bea0a81a0c09cf4_20160921_970f1dd44526_4738 {
  meta:
    description = "datamaliciousorder - from files 20160921_24a000738e40009c8bea0a81a0c09cf4.js, 20160921_970f1dd445269cda0ba5e6f9fd675983.js, 20160921_a31336f192353e1997fed06b582e1aef.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "f61bde20fd51cb3330f21d75680b7197049050166838d3ae36cae4b7521bfd50"
    hash2       = "eb33bb458042e91be0620012d2d05aaafd9742abb0880d1389b5c02b834e9290"
    hash3       = "762774d5263bffcad635355a63715b9cd26c09b53efe134be033e8dff5062b47"

  strings:
    $s1 = "unction f000(){return \"Yi\";})(),(function f000(){return \"Qz\";})(),(function f000(){return \"Do\";})(),(function f000(){retur" ascii
    $s2 = "ction f000(){return \"GGn\";})(),(function f000(){return \"KXg\";})(),(function f000(){return \"Zj\";})(),(function f000(){retur" ascii
    $s3 = "urn \"Kw\";})(),(function f000(){return \"XTn\";})(),(function f000(){return \"Do\";})(),(function f000(){return \"TRc\";})(),(f" ascii
    $s4 = "turn \"RPt\";})(),(function f000(){return \"Qz\";})(),(function f000(){return \"Do\";})(),(function f000(){return \"Zj\";})(),(f" ascii
    $s5 = "f000(){return \"WIj\";})(),(function f000(){return \"RPt\";})(),(function f000(){return \"Qz\";})(),(function f000(){return \"KX" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}