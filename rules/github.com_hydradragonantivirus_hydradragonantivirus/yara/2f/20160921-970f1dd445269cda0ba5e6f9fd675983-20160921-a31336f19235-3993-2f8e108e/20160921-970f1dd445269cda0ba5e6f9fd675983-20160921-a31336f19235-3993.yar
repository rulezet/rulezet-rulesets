rule _20160921_970f1dd445269cda0ba5e6f9fd675983_20160921_a31336f19235_3993 {
  meta:
    description = "datamaliciousorder - from files 20160921_970f1dd445269cda0ba5e6f9fd675983.js, 20160921_a31336f192353e1997fed06b582e1aef.js, 20160921_dff46b67b973e99ec02248f10c2f55c2.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "eb33bb458042e91be0620012d2d05aaafd9742abb0880d1389b5c02b834e9290"
    hash2       = "762774d5263bffcad635355a63715b9cd26c09b53efe134be033e8dff5062b47"
    hash3       = "2ea0ce06677c6aad57b6618a39beaa56b2c9060cb989c2213eb782aca5d747c2"

  strings:
    $s1 = "){return \"Do\";})(),(function f000(){return \"KXg\";})(),(function f000(){return \"TKl\";})(),(function f000(){return \"ZFe\";}" ascii
    $s2 = "on f000(){return \"DNa\";})(),(function f000(){return \"Sj\";})(),(function f000(){return \"Qj\";})(),(function f000(){return \"" ascii
    $s3 = "(){return \"WIj\";})(),(function f000(){return \"KXg\";})(),(function f000(){return \"Do\";})(),(function f000(){return \"ZFe\";" ascii
    $s4 = "urn \"ZGq\";})(),(function f000(){return \"PTi\";})(),(function f000(){return \"RVb\";})(),(function f000(){return \"GGn\";})()," ascii
    $s5 = "eturn \"TRc\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"Fs\";})(),(function f000(){return \"GGn\";})()" ascii
    $s6 = "rn \"ZFe\";})(),(function f000(){return \"TRc\";})(),(function f000(){return \"WIj\";})(),(function f000(){return \"ZFe\";})(),(" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}