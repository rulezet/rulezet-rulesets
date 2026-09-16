rule _20160921_9eb4e3262a9bc5c5f03ba0b7b62a3347_20160921_dd3003e8f162_5594 {
  meta:
    description = "datamaliciousorder - from files 20160921_9eb4e3262a9bc5c5f03ba0b7b62a3347.js, 20160921_dd3003e8f16270410cd847da3878f1fc.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "03bf8e47f97cab996cc7f2d8147659dc1143ccbe1fd09af6b8689379f7263407"
    hash2       = "484cc3f4c9cc3a29ae3ad53bb6d47be99d119531836a636c664a77fc891b38fc"

  strings:
    $s1 = "k(){return \"GJx\";})(),(function fuck(){return \"UXf\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"MBg" ascii
    $s2 = "ction fuck(){return \"IPu\";})(),(function fuck(){return \"Zy\";})(),(function fuck(){return \"Za\";})(),(function fuck(){return" ascii
    $s3 = "fuck(){return \"Np\";})(),(function fuck(){return \"Np\";})(),(function fuck(){return \"NKq\";})(),(function fuck(){return \"GNm" ascii
    $s4 = " \"Ve\";})(),(function fuck(){return \"Ik\";})(),(function fuck(){return \"UOe\";})(),(function fuck(){return \"IPu\";})(),(func" ascii
    $s5 = "ck(){return \"LGo\";})(),(function fuck(){return \"Hs\";})(),(function fuck(){return \"Jo\";})(),(function fuck(){return \"Np\";" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}