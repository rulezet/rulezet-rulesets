rule _20160921_3e5e21af311d364f73107419b54e74e3_20160921_975c5c13ffec_5021 {
  meta:
    description = "datamaliciousorder - from files 20160921_3e5e21af311d364f73107419b54e74e3.js, 20160921_975c5c13ffec0e2608898a142a2baed7.js, 20160921_f1cc02f488792b7161849f8d15549315.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "8b6cb861af32c3db5ac97103bfe3b904e62a9eee40ed51764665b556005b9510"
    hash2       = "4635f6ab0f307c878451c2e13b93f8c364364fd9dbd9b0a493d7990bc3eb3c17"
    hash3       = "a4438fd9b6e1eb385945338a0e8eaf272adfda2172cb3659bc36af2d1cc76ce5"

  strings:
    $s1 = "\"NBs\";})(),(function f000(){return \"Yi\";})(),(function f000(){return \"DIa\";})(),(function f000(){return \"DIa\";})(),(func" ascii
    $s2 = " f000(){return \"Br\";})(),(function f000(){return \"DIa\";})(),(function f000(){return \"Zj\";})(),(function f000(){return \"MM" ascii
    $s3 = "j\";})(),(function f000(){return \"Rh\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"WIj\";})(),(function" ascii
    $s4 = "turn \"Do\";})(),(function f000(){return \"TRc\";})(),(function f000(){return \"QDg\";})(),(function f000(){return \"Br\";})(),(" ascii
    $s5 = "tion f000(){return \"MMz\";})(),(function f000(){return \"MKa\";})()];" fullword ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}