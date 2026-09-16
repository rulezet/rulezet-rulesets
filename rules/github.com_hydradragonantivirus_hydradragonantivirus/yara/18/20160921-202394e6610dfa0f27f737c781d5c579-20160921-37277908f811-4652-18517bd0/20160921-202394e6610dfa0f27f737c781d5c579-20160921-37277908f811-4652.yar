rule _20160921_202394e6610dfa0f27f737c781d5c579_20160921_37277908f811_4652 {
  meta:
    description = "datamaliciousorder - from files 20160921_202394e6610dfa0f27f737c781d5c579.js, 20160921_37277908f8111ad292e17a84927fe01d.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "d10df61dcb3a781b5266597c0f1a9d52066cebbebf5196ad93fd81855575ed11"
    hash2       = "cac56e804b2f49b3fcd9bbc13fbdc4deb3a0ef68848e6527c15ab41f1104f286"

  strings:
    $s1 = "Aa\";})(),(function f000(){return \"Rh\";})(),(function f000(){return \"XTn\";})(),(function f000(){return \"GGn\";})(),(functio" ascii
    $s2 = "turn \"DYx\";})(),(function f000(){return \"Yi\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"MDb\";})()," ascii
    $s3 = "){return \"MDb\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"Nv\";})(),(function f000(){return \"ZFe\";}" ascii
    $s4 = "nction f000(){return \"WIj\";})(),(function f000(){return \"QDg\";})(),(function f000(){return \"DYs\";})(),(function f000(){ret" ascii
    $s5 = "(){return \"Tn\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"KDh\";})(),(function f000(){return \"TKp\";" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}