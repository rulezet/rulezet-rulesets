rule _20160921_2bac0af1f20f4cf23b85236dea7e2f73_20160921_ad0fbcfca87e_4807 {
  meta:
    description = "datamaliciousorder - from files 20160921_2bac0af1f20f4cf23b85236dea7e2f73.js, 20160921_ad0fbcfca87e48302530672c4ceab093.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "ac846ac68af7b06cbf71b32cbfb1cee6c1f6cd131d52124bb877e0b27979fd81"
    hash2       = "481451a3850055fd2d398d5707171f67d2aa3cd019214d6b67f539efc81ca7bb"

  strings:
    $s1 = "ction fuck(){return \"Jo\";})(),(function fuck(){return \"IRn\";})(),(function fuck(){return \"MBg\";})(),(function fuck(){retur" ascii
    $s2 = ";})(),(function fuck(){return \"LGo\";})(),(function fuck(){return \"RAi\";})(),(function fuck(){return \"Hs\";})(),(function fu" ascii
    $s3 = "){return \"IPu\";})(),(function fuck(){return \"UOe\";})(),(function fuck(){return \"Jo\";})(),(function fuck(){return \"ADy\";}" ascii
    $s4 = "on fuck(){return \"Jo\";})(),(function fuck(){return \"Np\";})(),(function fuck(){return \"RAi\";})(),(function fuck(){return \"" ascii
    $s5 = " \"Jo\";})(),(function fuck(){return \"ADy\";})(),(function fuck(){return \"NKq\";})(),(function fuck(){return \"GNm\";})(),(fun" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}