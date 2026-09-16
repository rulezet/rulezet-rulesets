rule _20160921_3688778166acb8f4f21b3c1d67ada442_20160921_b23a0d871d76_1474 {
  meta:
    description = "datamaliciousorder - from files 20160921_3688778166acb8f4f21b3c1d67ada442.js, 20160921_b23a0d871d76c64a3c71f0b0f52faaa8.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "03559b6095f398f17a62ec1f50c0a70c4b4074a67f6b8e3a51dfe026b238b085"
    hash2       = "02969139df11550b994530c0bcbc6d946b6e49105015e9475f5de3942d78e5a1"

  strings:
    $s1  = "urn \"Ug\";})(),(function fuck(){return \"Yk\";})(),(function fuck(){return \"DAa\";})(),(function fuck(){return \"DRx\";})(),(f" ascii
    $s2  = "(function fuck(){return \"Yk\";})(),(function fuck(){return \"Jg\";})(),(function fuck(){return \"RAi\";})(),(function fuck(){re" ascii
    $s3  = "),(function fuck(){return \"UOe\";})(),(function fuck(){return \"DRx\";})(),(function fuck(){return \"GJx\";})(),(function fuck(" ascii
    $s4  = ",(function fuck(){return \"Ot\";})(),(function fuck(){return \"GWo\";})(),(function fuck(){return \"DRx\";})(),(function fuck(){" ascii
    $s5  = "k(){return \"DRx\";})(),(function fuck(){return \"CCb\";})(),(function fuck(){return \"Yk\";})(),(function fuck(){return \"Ar\";" ascii
    $s6  = ";})(),(function fuck(){return \"Hs\";})(),(function fuck(){return \"RAi\";})(),(function fuck(){return \"NKq\";})(),(function fu" ascii
    $s7  = " fuck(){return \"Jh\";})(),(function fuck(){return \"USf\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"D" ascii
    $s8  = " fuck(){return \"DRx\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"YQt\";})(),(function fuck(){return \"" ascii
    $s9  = " fuck(){return \"DRx\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"YQt\";})(),(function fuck(){return \"" ascii
    $s10 = "(){return \"Hs\";})(),(function fuck(){return \"Vb\";})(),(function fuck(){return \"LGo\";})(),(function fuck(){return \"Jo\";})" ascii
    $s11 = "fuck(){return \"YQt\";})(),(function fuck(){return \"Ik\";})(),(function fuck(){return \"UOe\";})(),(function fuck(){return \"DR" ascii
    $s12 = "(),(function fuck(){return \"YAv\";})(),(function fuck(){return \"USf\";})(),(function fuck(){return \"DRx\";})(),(function fuck" ascii
    $s13 = "),(function fuck(){return \"IPu\";})(),(function fuck(){return \"XFd\";})(),(function fuck(){return \"AUx\";})(),(function fuck(" ascii

  condition:
    (uint16(0) == 0x2f0a and (8 of them)
    ) or (all of them)
}