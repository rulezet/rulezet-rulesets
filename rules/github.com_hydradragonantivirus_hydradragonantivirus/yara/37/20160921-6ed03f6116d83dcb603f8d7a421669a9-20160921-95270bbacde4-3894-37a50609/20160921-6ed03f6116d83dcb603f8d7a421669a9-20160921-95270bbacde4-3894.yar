rule _20160921_6ed03f6116d83dcb603f8d7a421669a9_20160921_95270bbacde4_3894 {
  meta:
    description = "datamaliciousorder - from files 20160921_6ed03f6116d83dcb603f8d7a421669a9.js, 20160921_95270bbacde4afcb3c799d7a0643809d.js, 20160921_b15ce64784b080eff109e1bd1b00ebf6.js, 20160921_e6569e3fc498e9fab243cf8dcef2ac51.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "7f10930e3c0bd956023b78dabf743464a690cb292b06d107d010614acff421c1"
    hash2       = "6cab57b5e35c3714b482592a77f0edbdc9fedb8c6e508d57b8cf63dfd719f5db"
    hash3       = "e78e24f62fb93be4551c02ce2a2a27421a39d4a9d5c77d37c7518adf9e53ce65"
    hash4       = "d08c501a52afbdcde7669d2b9c40865025e38aa75b2aebf8c71433565dbc7010"

  strings:
    $s1 = "n\";})(),(function f000(){return \"XTn\";})(),(function f000(){return \"TKl\";})(),(function f000(){return \"Zj\";})(),(function" ascii
    $s2 = "eturn \"Kw\";})(),(function f000(){return \"Yi\";})(),(function f000(){return \"Do\";})(),(function f000(){return \"TRc\";})(),(" ascii
    $s3 = "0(){return \"GGn\";})(),(function f000(){return \"Qz\";})(),(function f000(){return \"TKl\";})(),(function f000(){return \"Do\";" ascii
    $s4 = " \"Do\";})(),(function f000(){return \"XTn\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"Mu\";})(),(func" ascii
    $s5 = "(function f000(){return \"OUx\";})(),(function f000(){return \"RPt\";})(),(function f000(){return \"RPt\";})(),(function f000(){" ascii
    $s6 = "nction f000(){return \"TRc\";})(),(function f000(){return \"WIj\";})(),(function f000(){return \"Qz\";})(),(function f000(){retu" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}