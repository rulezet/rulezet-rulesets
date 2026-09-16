rule _20160921_7e15ac2755366d4644a83de8ec9c1a47_20160921_91734b00fd54_3058 {
  meta:
    description = "datamaliciousorder - from files 20160921_7e15ac2755366d4644a83de8ec9c1a47.js, 20160921_91734b00fd54cd3dd10c5f20c35d7864.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "97eaf7c50f22bfc94f97a02e5e83a8f1fb3583717fb9f4a6666ae882ea4d6f55"
    hash2       = "cdae8af0c395dfe20c83f759c05d2fd6ae2859606871798c6b3a7a12257c7f70"

  strings:
    $s1 = "urn \"Et\";})(),(function fuck(){return \"Jh\";})(),(function fuck(){return \"Ai\";})(),(function fuck(){return \"DRx\";})(),(fu" ascii
    $s2 = "{return \"DRx\";})(),(function fuck(){return \"Zy\";})(),(function fuck(){return \"Wo\";})(),(function fuck(){return \"Av\";})()" ascii
    $s3 = "tion fuck(){return \"Wo0\";})(),(function fuck(){return \"Xw\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return" ascii
    $s4 = "uck(){return \"Vf\";})(),(function fuck(){return \"Ug\";})(),(function fuck(){return \"SUi\";})(),(function fuck(){return \"DRx" ascii
    $s5 = "Rx\";})(),(function fuck(){return \"Ug\";})(),(function fuck(){return \"Jh\";})(),(function fuck(){return \"LGo\";})(),(function" ascii
    $s6 = "function fuck(){return \"Wo\";})(),(function fuck(){return \"UXf\";})(),(function fuck(){return \"Np\";})(),(function fuck(){ret" ascii
    $s7 = "\";})(),(function fuck(){return \"Ai\";})(),(function fuck(){return \"Hs\";})(),(function fuck(){return \"IRn\";})(),(function f" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}