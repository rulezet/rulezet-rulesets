rule _20160921_91af5c220d1ea27d72d05f472ba8fa16_20160921_bd40742bedf8_5543 {
  meta:
    description = "datamaliciousorder - from files 20160921_91af5c220d1ea27d72d05f472ba8fa16.js, 20160921_bd40742bedf80aa0091b1fafd0a7ba4b.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "d8a5c3b8bd7307238c3f0a133635143674d5db84b7c5615a145a8bea310c68de"
    hash2       = "85233a675e78f03dbcaaf2a32253b0d4a36e5c5e7008041477e560a514d38729"

  strings:
    $s1 = "\"Bz\";})(),(function fuck(){return \"GNm\";})(),(function fuck(){return \"Bz\";})(),(function fuck(){return \"Oh\";})(),(functi" ascii
    $s2 = "eturn \"Vb\";})(),(function fuck(){return \"LGo\";})(),(function fuck(){return \"USf\";})(),(function fuck(){return \"IPu\";})()" ascii
    $s3 = "on fuck(){return \"DRx\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"USf\";})(),(function fuck(){return " ascii
    $s4 = "eturn \"MBg\";})(),(function fuck(){return \"LGo\";})(),(function fuck(){return \"Jo\";})(),(function fuck(){return \"IPu\";})()" ascii
    $s5 = "})(),(function fuck(){return \"TTs\";})(),(function fuck(){return \"IKv\";})(),(function fuck(){return \"USf\";})(),(function fu" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}