rule _20160921_1bb9bdcf05b8f8acd28d5286e804d5cc_20160921_3214ea252f2a_3465 {
  meta:
    description = "datamaliciousorder - from files 20160921_1bb9bdcf05b8f8acd28d5286e804d5cc.js, 20160921_3214ea252f2a25e018a03ee43ce952f5.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "3937dec3a8d946e214facedccfe7f35e65dbd446a77d077a09996638d7524444"
    hash2       = "e406c80b4ad80ad1898c09cec0694086bfb24caedb8bc3bb213513d0b4232bd3"

  strings:
    $s1 = "\";})(),(function fuck(){return \"TTs\";})(),(function fuck(){return \"LGo\";})(),(function fuck(){return \"ADy\";})(),(function" ascii
    $s2 = "on fuck(){return \"Jo\";})(),(function fuck(){return \"Hs\";})(),(function fuck(){return \"IRn\";})(),(function fuck(){return \"" ascii
    $s3 = "turn \"Jo\";})(),(function fuck(){return \"Jo\";})(),(function fuck(){return \"Vb\";})(),(function fuck(){return \"IRn\";})(),(f" ascii
    $s4 = "){return \"Jo\";})(),(function fuck(){return \"ADy\";})(),(function fuck(){return \"IRn\";})(),(function fuck(){return \"MBg\";}" ascii
    $s5 = "rn \"Jo\";})(),(function fuck(){return \"Np\";})(),(function fuck(){return \"IRn\";})(),(function fuck(){return \"MBg\";})(),(fu" ascii
    $s6 = "tion fuck(){return \"IPu\";})(),(function fuck(){return \"LGo\";})(),(function fuck(){return \"UOe\";})(),(function fuck(){retur" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}