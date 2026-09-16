rule _20160921_694d4629e99fd1d23d60bc73e0e28e30_20160921_e3aa4388897e_3025 {
  meta:
    description = "datamaliciousorder - from files 20160921_694d4629e99fd1d23d60bc73e0e28e30.js, 20160921_e3aa4388897e55faa45b78b5304a0796.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "01147c2f2f43df58f5a1b60481a04add7d73eba030abaeed3f9dedb1fd3574e4"
    hash2       = "2891f4105f11c496e2a838e51e47950b803da8c03fe0cd132c2ad23839c0ca37"

  strings:
    $s1 = "(),(function fuck(){return \"PDf\";})(),(function fuck(){return \"DRx\";})(),(function fuck(){return \"Ot\";})(),(function fuck(" ascii
    $s2 = "ck(){return \"Vf\";})(),(function fuck(){return \"MUs\";})(),(function fuck(){return \"DRx\";})(),(function fuck(){return \"YQt" ascii
    $s3 = "turn \"DRx\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"Hs\";})(),(function fuck(){return \"Jh\";})(),(" ascii
    $s4 = " fuck(){return \"ADy\";})(),(function fuck(){return \"DRx\";})(),(function fuck(){return \"XFd\";})(),(function fuck(){return \"" ascii
    $s5 = "ck(){return \"LGo\";})(),(function fuck(){return \"PDf\";})(),(function fuck(){return \"NKq\";})(),(function fuck(){return \"Ug" ascii
    $s6 = "rn \"Ai\";})(),(function fuck(){return \"Na\";})(),(function fuck(){return \"DRx\";})(),(function fuck(){return \"Oh\";})(),(fun" ascii
    $s7 = "(){return \"IPu\";})(),(function fuck(){return \"Jo\";})(),(function fuck(){return \"KVh\";})(),(function fuck(){return \"ADy\";" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}