rule _20160921_4cbbeff2b84f01cc3ab55f4eb29babb2_20160921_64060d97e498_5130 {
  meta:
    description = "datamaliciousorder - from files 20160921_4cbbeff2b84f01cc3ab55f4eb29babb2.js, 20160921_64060d97e498db57bf68dbb08be86bba.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "698c46439ef391a98b04ac1a2759ff8a84b30a9c444a7575c5290eb0aa4b66b9"
    hash2       = "30a02b9f75ed0112affe2c698cfdbe2ec2a5bc4d8248ac34ebe13e072bd212f0"

  strings:
    $s1 = " \"MBg\";})(),(function fuck(){return \"LGo\";})(),(function fuck(){return \"LGo\";})(),(function fuck(){return \"USf\";})(),(fu" ascii
    $s2 = "),(function fuck(){return \"ADy\";})(),(function fuck(){return \"Vb\";})(),(function fuck(){return \"IPu\";})(),(function fuck()" ascii
    $s3 = "ck(){return \"MBg\";})(),(function fuck(){return \"Hs\";})(),(function fuck(){return \"Vb\";})(),(function fuck(){return \"RAi\"" ascii
    $s4 = "n fuck(){return \"MBg\";})(),(function fuck(){return \"IKv\";})(),(function fuck(){return \"Np\";})(),(function fuck(){return \"" ascii
    $s5 = "turn \"Ot\";})(),(function fuck(){return \"ZVi\";})(),(function fuck(){return \"UOe\";})(),(function fuck(){return \"IPu\";})()," ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}