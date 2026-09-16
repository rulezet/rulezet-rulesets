rule _20160921_2c5e8ccbd48636e7c625aae6ef954560_20160921_e67c85fc609b_3583 {
  meta:
    description = "datamaliciousorder - from files 20160921_2c5e8ccbd48636e7c625aae6ef954560.js, 20160921_e67c85fc609bef1c06233d9dc655b074.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "70244ca5fa124af09b1f94729567c09dbc52c05035ee7d20cbe87d35e1fe63c8"
    hash2       = "372b553e13a1b2dacf2c8938d6c7953212ff8112978d88f8aa1425ffa2ef21de"

  strings:
    $s1 = "unction fuck(){return \"IPu\";})(),(function fuck(){return \"Oh\";})(),(function fuck(){return \"Ve\";})(),(function fuck(){retu" ascii
    $s2 = "turn \"Yk\";})(),(function fuck(){return \"Na\";})(),(function fuck(){return \"LGo\";})(),(function fuck(){return \"MOj\";})(),(" ascii
    $s3 = "ck(){return \"Qh\";})(),(function fuck(){return \"Ve\";})(),(function fuck(){return \"Dc\";})(),(function fuck(){return \"LGo\";" ascii
    $s4 = "(){return \"IOs\";})(),(function fuck(){return \"USf\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"DRx\"" ascii
    $s5 = "v\";})(),(function fuck(){return \"RAi\";})(),(function fuck(){return \"IRn\";})(),(function fuck(){return \"NKq\";})(),(functio" ascii
    $s6 = "uck(){return \"TTs\";})(),(function fuck(){return \"DWe\";})(),(function fuck(){return \"MIl\";})(),(function fuck(){return \"Jg" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}