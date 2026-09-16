rule _20160921_06a7c56eaf19048ede06f33b655f2bc5_20160921_bd6b4f506f52_4270 {
  meta:
    description = "datamaliciousorder - from files 20160921_06a7c56eaf19048ede06f33b655f2bc5.js, 20160921_bd6b4f506f527835a48516850a16c1a6.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "3971833c2ab49de293c47181e999db88e5cad0eaddc5aa38a2516eeac1cab29d"
    hash2       = "ccc844c2bc8943a231b37e8fbf1d55bab57686844fc9486bd597d3b00ae72c70"

  strings:
    $s1 = "return \"IRn\";})(),(function fuck(){return \"MBg\";})(),(function fuck(){return \"Vb\";})(),(function fuck(){return \"YQt\";})(" ascii
    $s2 = ")(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"XCr\";})(),(function fuck(){return \"FJs\";})(),(function fuc" ascii
    $s3 = "ction fuck(){return \"RAi\";})(),(function fuck(){return \"AUx\";})(),(function fuck(){return \"IRn\";})(),(function fuck(){retu" ascii
    $s4 = "u\";})(),(function fuck(){return \"Nm\";})(),(function fuck(){return \"Xg\";})(),(function fuck(){return \"Vb\";})(),(function f" ascii
    $s5 = "nction fuck(){return \"MIl\";})(),(function fuck(){return \"GWo\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){ret" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}