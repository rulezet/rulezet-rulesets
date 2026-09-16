rule _20160921_1c739a510b202fd8658c1445b926e28b_20160921_dd42e850834f_25 {
  meta:
    description = "datamaliciousorder - from files 20160921_1c739a510b202fd8658c1445b926e28b.js, 20160921_dd42e850834f3af27a08edf609a699b5.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "ef5e44b6b8f05f9e4eadc507955ef770936acdd360f7dcfe6bb70a36427b04b7"
    hash2       = "d7708087ab30a8d0d937f9d460512c05c37534c0d3c387bd3e1dd7fcb84fdc58"

  strings:
    $s1  = "k(){return \"Za\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"Wo\";})(),(function fuck(){return \"PDf\";" ascii
    $s2  = "urn \"UOe\";})(),(function fuck(){return \"USf\";})(),(function fuck(){return \"GNm\";})(),(function fuck(){return \"ADy\";})()," ascii
    $s3  = "nction fuck(){return \"ZVi\";})(),(function fuck(){return \"TTs\";})(),(function fuck(){return \"Yk\";})(),(function fuck(){retu" ascii
    $s4  = "fuck(){return \"LGo\";})(),(function fuck(){return \"YQt\";})(),(function fuck(){return \"GNm\";})(),(function fuck(){return \"I" ascii
    $s5  = ")(),(function fuck(){return \"Xg\";})(),(function fuck(){return \"Ik\";})(),(function fuck(){return \"GWo\";})(),(function fuck(" ascii
    $s6  = "nction fuck(){return \"IKv\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"LGo\";})(),(function fuck(){ret" ascii
    $s7  = "n fuck(){return \"IPu\";})(),(function fuck(){return \"Nm\";})(),(function fuck(){return \"Ai\";})(),(function fuck(){return \"A" ascii
    $s8  = "unction fuck(){return \"AUx\";})(),(function fuck(){return \"YQt\";})(),(function fuck(){return \"IRn\";})(),(function fuck(){re" ascii
    $s9  = "})(),(function fuck(){return \"XHj\";})(),(function fuck(){return \"GWo\";})(),(function fuck(){return \"UOe\";})(),(function fu" ascii
    $s10 = " \"LGo\";})(),(function fuck(){return \"AUx\";})(),(function fuck(){return \"LGo\";})(),(function fuck(){return \"IPu\";})(),(fu" ascii
    $s11 = "nction fuck(){return \"IOs\";})(),(function fuck(){return \"AUx\";})(),(function fuck(){return \"MOj\";})(),(function fuck(){ret" ascii
    $s12 = "rn \"GJx\";})(),(function fuck(){return \"YAv\";})(),(function fuck(){return \"Vb\";})(),(function fuck(){return \"MOj\";})(),(f" ascii
    $s13 = "fuck(){return \"MIl\";})(),(function fuck(){return \"EHo\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"D" ascii
    $s14 = "k(){return \"USf\";})(),(function fuck(){return \"TTs\";})(),(function fuck(){return \"USf\";})(),(function fuck(){return \"AUx" ascii
    $s15 = "ion fuck(){return \"Za\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"XCr\";})(),(function fuck(){return " ascii
    $s16 = "){return \"Za\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"Ot\";})(),(function fuck(){return \"PDf\";})" ascii
    $s17 = "})(),(function fuck(){return \"IRn\";})(),(function fuck(){return \"OQr\";})(),(function fuck(){return \"MIl\";})(),(function fu" ascii
    $s18 = "fuck(){return \"IPu\";})(),(function fuck(){return \"OQr\";})(),(function fuck(){return \"GJx\";})(),(function fuck(){return \"E" ascii
    $s19 = " \"Za\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"Vf\";})(),(function fuck(){return \"YAv\";})(),(func" ascii
    $s20 = "return \"Vb\";})(),(function fuck(){return \"GNm\";})(),(function fuck(){return \"GNm\";})(),(function fuck(){return \"MOj\";})(" ascii

  condition:
    (uint16(0) == 0x2f0a and (8 of them)
    ) or (all of them)
}