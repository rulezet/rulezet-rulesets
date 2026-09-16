rule _20160921_1766f5c818d6371cb36488c98158ccd2_20160921_37277908f811_1663 {
  meta:
    description = "datamaliciousorder - from files 20160921_1766f5c818d6371cb36488c98158ccd2.js, 20160921_37277908f8111ad292e17a84927fe01d.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "4d8985b767534ef1312401b6a38570477e0c87ed4ef37c945eee55179929c0a4"
    hash2       = "cac56e804b2f49b3fcd9bbc13fbdc4deb3a0ef68848e6527c15ab41f1104f286"

  strings:
    $s1  = "){return \"Uo\";})(),(function f000(){return \"Oe\";})(),(function f000(){return \"WIj\";})(),(function f000(){return \"RPt\";})" ascii
    $s2  = "),(function f000(){return \"Mu\";})(),(function f000(){return \"Yi\";})(),(function f000(){return \"Qz\";})(),(function f000(){r" ascii
    $s3  = "\"TKl\";})(),(function f000(){return \"Qz\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"MDb\";})(),(func" ascii
    $s4  = "){return \"Tn\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"Sj\";})(),(function f000(){return \"SGs\";})" ascii
    $s5  = "eturn \"KXg\";})(),(function f000(){return \"RPt\";})(),(function f000(){return \"KXg\";})(),(function f000(){return \"Zj\";})()" ascii
    $s6  = "0(){return \"GGn\";})(),(function f000(){return \"Yi\";})(),(function f000(){return \"Qz\";})(),(function f000(){return \"TKl\";" ascii
    $s7  = "j\";})(),(function f000(){return \"WIj\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"Uo\";})(),(function" ascii
    $s8  = "nction f000(){return \"Qz\";})(),(function f000(){return \"DIa\";})(),(function f000(){return \"GGn\";})(),(function f000(){retu" ascii
    $s9  = "tion f000(){return \"KXg\";})(),(function f000(){return \"RPt\";})(),(function f000(){return \"Yi\";})(),(function f000(){return" ascii
    $s10 = "{return \"Qj\";})(),(function f000(){return \"Qj\";})(),(function f000(){return \"OMd\";})(),(function f000(){return \"GGn\";})(" ascii
    $s11 = " f000(){return \"Sq\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"QDg\";})(),(function f000(){return \"Q" ascii

  condition:
    (uint16(0) == 0x2f0a and (8 of them)
    ) or (all of them)
}