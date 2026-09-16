rule _20160921_203e0165d7eb1b32389bd0efd4bc9546_20160921_70b567ca258b_3499 {
  meta:
    description = "datamaliciousorder - from files 20160921_203e0165d7eb1b32389bd0efd4bc9546.js, 20160921_70b567ca258b3c505e14f3c712366f09.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "b9112c30f4cc79af123a3f3e13b1e01a29f2419955988701cb25a673fdfe684d"
    hash2       = "8cf06551c554a2db81fe1bf37b069b40e558f931913e7d2572bdd18b36f57c73"

  strings:
    $s1 = "USf\";})(),(function fuck(){return \"MBg\";})(),(function fuck(){return \"Py\";})(),(function fuck(){return \"NKq\";})(),(functi" ascii
    $s2 = "r\";})(),(function fuck(){return \"LGo\";})(),(function fuck(){return \"RAi\";})(),(function fuck(){return \"UOe\";})(),(functio" ascii
    $s3 = "rn \"Ai\";})(),(function fuck(){return \"FJs\";})(),(function fuck(){return \"Hs\";})(),(function fuck(){return \"DRx\";})(),(fu" ascii
    $s4 = "){return \"OPz\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"ZLd\";})(),(function fuck(){return \"Qh\";}" ascii
    $s5 = "rn \"YQt\";})(),(function fuck(){return \"Wo0\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"DRx\";})(),(" ascii
    $s6 = " \"IRn\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"Ff\";})(),(function fuck(){return \"MBg\";})(),(fun" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}