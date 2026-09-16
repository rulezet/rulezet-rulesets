rule _20160921_731724a743a10eb03d2ee3a92239f369_20160921_970f1dd44526_5394 {
  meta:
    description = "datamaliciousorder - from files 20160921_731724a743a10eb03d2ee3a92239f369.js, 20160921_970f1dd445269cda0ba5e6f9fd675983.js, 20160921_a31336f192353e1997fed06b582e1aef.js, 20160921_f1b8df0ab75abc0c2b3be738559f2ab3.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "a7ac1561634dc1fa8b18cc98ccf432021ed2e8b16132f60e88757d855dedeb94"
    hash2       = "eb33bb458042e91be0620012d2d05aaafd9742abb0880d1389b5c02b834e9290"
    hash3       = "762774d5263bffcad635355a63715b9cd26c09b53efe134be033e8dff5062b47"
    hash4       = "dfdf24fc382cd60cf8d9c01ff0bca33ee060801ad2bd963895209ac610525301"

  strings:
    $s1 = "ction f000(){return \"Do\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"UOt\";})(),(function f000(){retur" ascii
    $s2 = "{return \"Oe\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"MMz\";})(),(function f000(){return \"MKa\";})" ascii
    $s3 = "000(){return \"Wb\";})(),(function f000(){return \"Do\";})(),(function f000(){return \"Zj\";})(),(function f000(){return \"KZr\"" ascii
    $s4 = "t\";})(),(function f000(){return \"Oe\";})(),(function f000(){return \"BQb\";})(),(function f000(){return \"UEg\";})(),(function" ascii
    $s5 = "return \"DIa\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"MMz\";})(),(function f000(){return \"MKa\";})" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}