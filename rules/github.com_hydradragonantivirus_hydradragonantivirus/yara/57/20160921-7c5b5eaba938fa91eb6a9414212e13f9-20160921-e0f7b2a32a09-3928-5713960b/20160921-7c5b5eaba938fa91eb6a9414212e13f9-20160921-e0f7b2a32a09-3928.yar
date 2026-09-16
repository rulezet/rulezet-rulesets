rule _20160921_7c5b5eaba938fa91eb6a9414212e13f9_20160921_e0f7b2a32a09_3928 {
  meta:
    description = "datamaliciousorder - from files 20160921_7c5b5eaba938fa91eb6a9414212e13f9.js, 20160921_e0f7b2a32a0967097baa59c67369ba3a.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "9b25331c24a00cfccf7bf1604f7df1d245543734bf5553f0a7c3c911bb74cbb8"
    hash2       = "d527617da74d553b6d56b37f7b101c14280b85e5e40e1f565fe396f8b97b29a2"

  strings:
    $s1 = ";})(),(function fuck(){return \"ADy\";})(),(function fuck(){return \"TTs\";})(),(function fuck(){return \"Zy\";})(),(function fu" ascii
    $s2 = "eturn \"Py\";})(),(function fuck(){return \"QTc\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"DRx\";})()" ascii
    $s3 = "on fuck(){return \"IPu\";})(),(function fuck(){return \"XCr\";})(),(function fuck(){return \"GJx\";})(),(function fuck(){return " ascii
    $s4 = "t\";})(),(function fuck(){return \"CCb\";})(),(function fuck(){return \"Dc\";})(),(function fuck(){return \"Jo\";})(),(function " ascii
    $s5 = "on fuck(){return \"IPu\";})(),(function fuck(){return \"XCr\";})(),(function fuck(){return \"CCb\";})(),(function fuck(){return " ascii
    $s6 = "eturn \"Wo\";})(),(function fuck(){return \"QTc\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"DRx\";})()" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}