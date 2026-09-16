rule _20160921_970f1dd445269cda0ba5e6f9fd675983_20160921_a31336f19235_5568 {
  meta:
    description = "datamaliciousorder - from files 20160921_970f1dd445269cda0ba5e6f9fd675983.js, 20160921_a31336f192353e1997fed06b582e1aef.js, 20160921_a3256642bcc1ce0dfec8677fe62bc590.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "eb33bb458042e91be0620012d2d05aaafd9742abb0880d1389b5c02b834e9290"
    hash2       = "762774d5263bffcad635355a63715b9cd26c09b53efe134be033e8dff5062b47"
    hash3       = "4af9ef65888b7e1a452f74c901f68872403712ef67ed9f79ac51c3bfb98c1f59"

  strings:
    $s1 = " f000(){return \"ZIi\";})(),(function f000(){return \"Km\";})(),(function f000(){return \"Iq\";})(),(function f000(){return \"BQ" ascii
    $s2 = "00(){return \"Ml\";})(),(function f000(){return \"Tn\";})(),(function f000(){return \"Oe\";})(),(function f000(){return \"Yz\";}" ascii
    $s3 = " f000(){return \"DIa\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"Uo\";})(),(function f000(){return \"M" ascii
    $s4 = ",(function f000(){return \"Oe\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"QDg\";})(),(function f000(){" ascii
    $s5 = "ction f000(){return \"YTp\";})(),(function f000(){return \"Mt\";})(),(function f000(){return \"UEg\";})(),(function f000(){retur" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}