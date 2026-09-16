rule _20160921_125bc6e32001cf9e335a6ab52f464add_20160921_56560f8d7ec6_266 {
  meta:
    description = "datamaliciousorder - from files 20160921_125bc6e32001cf9e335a6ab52f464add.js, 20160921_56560f8d7ec61c150afb741a4a7975e2.js, 20160921_ef83849d63779003debb3d7ec32b193e.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "85fd75eaf5744358778610f756047b2dcd2017e11bf6f105849c49d56486df9c"
    hash2       = "ba922e4e746eb45b8e98a88ec3071072c0850dbd5e2a359302331e1ae65210fb"
    hash3       = "8c488afd3d971ee89eb15305d884bacb01b91fa70760bea0aaf808120622dfa3"

  strings:
    $s1  = " fuck(){return \"Np\";})(),(function fuck(){return \"PDf\";})(),(function fuck(){return \"IRn\";})(),(function fuck(){return \"M" ascii
    $s2  = "(){return \"TTs\";})(),(function fuck(){return \"ADy\";})(),(function fuck(){return \"GNm\";})(),(function fuck(){return \"Vb\";" ascii
    $s3  = "urn \"ZVi\";})(),(function fuck(){return \"DRx\";})(),(function fuck(){return \"Zy\";})(),(function fuck(){return \"Sx\";})(),(f" ascii
    $s4  = "eturn \"Cd\";})(),(function fuck(){return \"Vb\";})(),(function fuck(){return \"ADy\";})(),(function fuck(){return \"UOe\";})()," ascii
    $s5  = "ction fuck(){return \"MBg\";})(),(function fuck(){return \"PDf\";})(),(function fuck(){return \"RAi\";})(),(function fuck(){retu" ascii
    $s6  = "unction fuck(){return \"IPu\";})(),(function fuck(){return \"PDf\";})(),(function fuck(){return \"IRn\";})(),(function fuck(){re" ascii
    $s7  = "urn \"Cd\";})(),(function fuck(){return \"ADy\";})(),(function fuck(){return \"NKq\";})(),(function fuck(){return \"Ug\";})(),(f" ascii
    $s8  = "eturn \"Vb\";})(),(function fuck(){return \"Cd\";})(),(function fuck(){return \"Vb\";})(),(function fuck(){return \"GNm\";})(),(" ascii
    $s9  = "\"Vb\";})(),(function fuck(){return \"ADy\";})(),(function fuck(){return \"Cd\";})(),(function fuck(){return \"IPu\";})(),(funct" ascii
    $s10 = "eturn \"Dc\";})(),(function fuck(){return \"RAi\";})(),(function fuck(){return \"TTs\";})(),(function fuck(){return \"Cd\";})()," ascii
    $s11 = "){return \"TTs\";})(),(function fuck(){return \"XHj\";})(),(function fuck(){return \"YAv\";})(),(function fuck(){return \"IPu\";" ascii
    $s12 = "o\";})(),(function fuck(){return \"GNm\";})(),(function fuck(){return \"ADy\";})(),(function fuck(){return \"IRn\";})(),(functio" ascii
    $s13 = "\"Vb\";})(),(function fuck(){return \"PDf\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"Ml\";})(),(funct" ascii
    $s14 = "urn \"Wo0\";})(),(function fuck(){return \"Py\";})(),(function fuck(){return \"GNm\";})(),(function fuck(){return \"IRn\";})(),(" ascii
    $s15 = "(){return \"LGo\";})(),(function fuck(){return \"Vb\";})(),(function fuck(){return \"Cd\";})(),(function fuck(){return \"IRn\";}" ascii
    $s16 = "){return \"IRn\";})(),(function fuck(){return \"MBg\";})(),(function fuck(){return \"PDf\";})(),(function fuck(){return \"LGo\";" ascii
    $s17 = " fuck(){return \"Vb\";})(),(function fuck(){return \"Cd\";})(),(function fuck(){return \"Np\";})(),(function fuck(){return \"IRn" ascii
    $s18 = "ction fuck(){return \"Vb\";})(),(function fuck(){return \"Cd\";})(),(function fuck(){return \"ADy\";})(),(function fuck(){return" ascii
    $s19 = "on fuck(){return \"RAi\";})(),(function fuck(){return \"UOe\";})(),(function fuck(){return \"GNm\";})(),(function fuck(){return " ascii
    $s20 = "(),(function fuck(){return \"Cd\";})(),(function fuck(){return \"RAi\";})(),(function fuck(){return \"Cd\";})(),(function fuck()" ascii

  condition:
    (uint16(0) == 0x2f0a and (8 of them)
    ) or (all of them)
}