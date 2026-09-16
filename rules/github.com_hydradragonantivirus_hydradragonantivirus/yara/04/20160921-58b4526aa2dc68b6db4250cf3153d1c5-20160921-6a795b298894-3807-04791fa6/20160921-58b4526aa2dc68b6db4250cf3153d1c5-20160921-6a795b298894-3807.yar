rule _20160921_58b4526aa2dc68b6db4250cf3153d1c5_20160921_6a795b298894_3807 {
  meta:
    description = "datamaliciousorder - from files 20160921_58b4526aa2dc68b6db4250cf3153d1c5.js, 20160921_6a795b29889480550a8440815b06fa7d.js, 20160921_7e2de7c26f136a1a958818752613cac3.js, 20160921_dc73cfa7a33eb762f38614c69a95919d.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "8879fc10234de7d36f536a9cdb49bc5cf37dfb897d610b0eeba644033852dd92"
    hash2       = "fb5890246703edf23742bd2e821c50d1610d87dc3d17ff4909414fae3bd26d96"
    hash3       = "540bec3c8538992ab2a631157eae2d03acb2afd24ba0842fcdbbcd7a792913b3"
    hash4       = "50e80269adbbca38f500219eaf7cec16f396b3d8a7c56d342b2e4839819ea598"

  strings:
    $s1 = "(){return \"TTs\";})(),(function fuck(){return \"Vb\";})(),(function fuck(){return \"Jo\";})(),(function fuck(){return \"Vb\";})" ascii
    $s2 = "n fuck(){return \"IPu\";})(),(function fuck(){return \"LGo\";})(),(function fuck(){return \"Vb\";})(),(function fuck(){return \"" ascii
    $s3 = "ion fuck(){return \"TTs\";})(),(function fuck(){return \"Vb\";})(),(function fuck(){return \"Jo\";})(),(function fuck(){return " ascii
    $s4 = "tion fuck(){return \"Vb\";})(),(function fuck(){return \"Jo\";})(),(function fuck(){return \"Jo\";})(),(function fuck(){return " ascii
    $s5 = "uck(){return \"Vb\";})(),(function fuck(){return \"Jo\";})(),(function fuck(){return \"USf\";})(),(function fuck(){return \"IRn" ascii
    $s6 = "turn \"Vb\";})(),(function fuck(){return \"ADy\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"DRx\";})()," ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}