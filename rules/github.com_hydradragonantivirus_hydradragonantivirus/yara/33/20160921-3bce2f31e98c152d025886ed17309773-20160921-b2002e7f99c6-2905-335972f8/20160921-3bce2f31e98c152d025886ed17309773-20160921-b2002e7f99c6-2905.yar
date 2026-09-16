rule _20160921_3bce2f31e98c152d025886ed17309773_20160921_b2002e7f99c6_2905 {
  meta:
    description = "datamaliciousorder - from files 20160921_3bce2f31e98c152d025886ed17309773.js, 20160921_b2002e7f99c6e0351a90c5fe98b8b775.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "9a668f4a1c8cd764f3d7afa71030b8b37f7ec8d0b0b42b9a93aa82346b5ae616"
    hash2       = "1e6376c7075a97cbb4e180ac5ea89ade4f5170dd182e1014b19fd2ed4aa33345"

  strings:
    $s1 = "nction f000(){return \"TKl\";})(),(function f000(){return \"KXg\";})(),(function f000(){return \"Yi\";})(),(function f000(){retu" ascii
    $s2 = "unction f000(){return \"GGn\";})(),(function f000(){return \"Br\";})(),(function f000(){return \"Wh\";})(),(function f000(){retu" ascii
    $s3 = "tion f000(){return \"Tn\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"Go\";})(),(function f000(){return " ascii
    $s4 = "\"Mu\";})(),(function f000(){return \"TKl\";})(),(function f000(){return \"RPt\";})(),(function f000(){return \"Do\";})(),(funct" ascii
    $s5 = "n \"DYx\";})(),(function f000(){return \"Yi\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"WIj\";})(),(fu" ascii
    $s6 = "000(){return \"Br\";})(),(function f000(){return \"DYx\";})(),(function f000(){return \"MJq\";})(),(function f000(){return \"DYx" ascii
    $s7 = "urn \"RPt\";})(),(function f000(){return \"KXg\";})(),(function f000(){return \"Do\";})(),(function f000(){return \"TRc\";})(),(" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}