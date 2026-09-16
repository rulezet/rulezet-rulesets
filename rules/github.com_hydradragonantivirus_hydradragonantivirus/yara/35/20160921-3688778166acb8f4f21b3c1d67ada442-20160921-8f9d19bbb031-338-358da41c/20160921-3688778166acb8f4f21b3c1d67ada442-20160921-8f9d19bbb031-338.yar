rule _20160921_3688778166acb8f4f21b3c1d67ada442_20160921_8f9d19bbb031_338 {
  meta:
    description = "datamaliciousorder - from files 20160921_3688778166acb8f4f21b3c1d67ada442.js, 20160921_8f9d19bbb031c21665ebbafad8d5ab55.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "03559b6095f398f17a62ec1f50c0a70c4b4074a67f6b8e3a51dfe026b238b085"
    hash2       = "b4039cc962a684523fe76faba20cbc27d33e0e6b0c86feb67e04127cf37a2fc4"

  strings:
    $s1  = "eturn \"We\";})(),(function fuck(){return \"Na\";})(),(function fuck(){return \"USf\";})(),(function fuck(){return \"IRn\";})()," ascii
    $s2  = "})(),(function fuck(){return \"Jo\";})(),(function fuck(){return \"Py\";})(),(function fuck(){return \"NKq\";})(),(function fuck" ascii
    $s3  = "turn \"Oh\";})(),(function fuck(){return \"Ve\";})(),(function fuck(){return \"YAv\";})(),(function fuck(){return \"RAi\";})(),(" ascii
    $s4  = " fuck(){return \"GWo\";})(),(function fuck(){return \"USf\";})(),(function fuck(){return \"MOj\";})(),(function fuck(){return \"" ascii
    $s5  = ")(),(function fuck(){return \"LGo\";})(),(function fuck(){return \"Py\";})(),(function fuck(){return \"Vb\";})(),(function fuck(" ascii
    $s6  = ",(function fuck(){return \"USf\";})(),(function fuck(){return \"UOe\";})(),(function fuck(){return \"UOe\";})(),(function fuck()" ascii
    $s7  = "function fuck(){return \"USf\";})(),(function fuck(){return \"Py\";})(),(function fuck(){return \"UOe\";})(),(function fuck(){re" ascii
    $s8  = "{return \"MBg\";})(),(function fuck(){return \"Vb\";})(),(function fuck(){return \"RAi\";})(),(function fuck(){return \"Py\";})(" ascii
    $s9  = " \"Ml\";})(),(function fuck(){return \"DHd\";})(),(function fuck(){return \"MOj\";})(),(function fuck(){return \"NKq\";})(),(fun" ascii
    $s10 = "){return \"Hs\";})(),(function fuck(){return \"LGo\";})(),(function fuck(){return \"LGo\";})(),(function fuck(){return \"IPu\";}" ascii
    $s11 = "n \"ADy\";})(),(function fuck(){return \"Vb\";})(),(function fuck(){return \"Py\";})(),(function fuck(){return \"Hs\";})(),(func" ascii
    $s12 = " \"Hs\";})(),(function fuck(){return \"UOe\";})(),(function fuck(){return \"UOe\";})(),(function fuck(){return \"ADy\";})(),(fun" ascii
    $s13 = " fuck(){return \"IPu\";})(),(function fuck(){return \"USf\";})(),(function fuck(){return \"ADy\";})(),(function fuck(){return \"" ascii
    $s14 = "),(function fuck(){return \"LGo\";})(),(function fuck(){return \"Py\";})(),(function fuck(){return \"USf\";})(),(function fuck()" ascii
    $s15 = "(){return \"Vb\";})(),(function fuck(){return \"Np\";})(),(function fuck(){return \"Py\";})(),(function fuck(){return \"IRn\";})" ascii
    $s16 = "n fuck(){return \"TTs\";})(),(function fuck(){return \"XHj\";})(),(function fuck(){return \"IOs\";})(),(function fuck(){return " ascii
    $s17 = "urn \"IPu\";})(),(function fuck(){return \"Hs\";})(),(function fuck(){return \"LGo\";})(),(function fuck(){return \"UOe\";})(),(" ascii
    $s18 = "(function fuck(){return \"RAi\";})(),(function fuck(){return \"Hs\";})(),(function fuck(){return \"Vb\";})(),(function fuck(){re" ascii
    $s19 = "ction fuck(){return \"Py\";})(),(function fuck(){return \"Jo\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return" ascii
    $s20 = "ction fuck(){return \"MBg\";})(),(function fuck(){return \"UOe\";})(),(function fuck(){return \"RAi\";})(),(function fuck(){retu" ascii

  condition:
    (uint16(0) == 0x2f0a and (8 of them)
    ) or (all of them)
}