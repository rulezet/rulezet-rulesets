rule _20160921_105b4651b7160ca47c8bc86d4da31c43_20160921_d29f34806a7d_1657 {
  meta:
    description = "datamaliciousorder - from files 20160921_105b4651b7160ca47c8bc86d4da31c43.js, 20160921_d29f34806a7d94f2bbb7a733fc4c43bc.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "8e64d089e7076541ade19a5701fb8571545dde4a6c002b31df5fef02095005f7"
    hash2       = "70ffc02d6ba6dee7d11e2b608cd1544f99d837ffc746455c17b70d5b07ba0ac9"

  strings:
    $s1  = "eturn \"IPu\";})(),(function fuck(){return \"Jo\";})(),(function fuck(){return \"MOj\";})(),(function fuck(){return \"NKq\";})()" ascii
    $s2  = " \"DRx\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"YQt\";})(),(function fuck(){return \"Nm\";})(),(fun" ascii
    $s3  = ";})(),(function fuck(){return \"IKv\";})(),(function fuck(){return \"Jo\";})(),(function fuck(){return \"OPz\";})(),(function fu" ascii
    $s4  = "})(),(function fuck(){return \"Nm\";})(),(function fuck(){return \"UXf\";})(),(function fuck(){return \"MBg\";})(),(function fuc" ascii
    $s5  = "){return \"Nm\";})(),(function fuck(){return \"DAa\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"MBg\";}" ascii
    $s6  = ",(function fuck(){return \"IPu\";})(),(function fuck(){return \"YQt\";})(),(function fuck(){return \"Nm\";})(),(function fuck(){" ascii
    $s7  = "turn \"OQr\";})(),(function fuck(){return \"GJx\";})(),(function fuck(){return \"Qh\";})(),(function fuck(){return \"FJs\";})()," ascii
    $s8  = "return \"UXf\";})(),(function fuck(){return \"Jo\";})(),(function fuck(){return \"MBg\";})(),(function fuck(){return \"Nm\";})()" ascii
    $s9  = ")(),(function fuck(){return \"Bz\";})(),(function fuck(){return \"CTm\";})(),(function fuck(){return \"Cd\";})(),(function fuck(" ascii
    $s10 = "urn \"Ot\";})(),(function fuck(){return \"USf\";})(),(function fuck(){return \"TTs\";})(),(function fuck(){return \"Jo\";})(),(f" ascii
    $s11 = "uck(){return \"Ai\";})(),(function fuck(){return \"Wo0\";})(),(function fuck(){return \"OPz\";})(),(function fuck(){return \"IPu" ascii

  condition:
    (uint16(0) == 0x2f0a and (8 of them)
    ) or (all of them)
}