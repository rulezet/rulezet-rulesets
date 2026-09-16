rule _20160921_22fd683e7973fc938e9d6980e5e81789_20160921_be8454f98b5a_4718 {
  meta:
    description = "datamaliciousorder - from files 20160921_22fd683e7973fc938e9d6980e5e81789.js, 20160921_be8454f98b5a24b3ec56590bd13ee274.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "c3583ada9b0a35137add948ee4bd3182a5f977a0dbcc3a39c01ee288f703d566"
    hash2       = "984696d2831d222abf66218ad54b440a2fd79bd47a7f1493a197576207321839"

  strings:
    $s1 = "turn \"Xw\";})(),(function fuck(){return \"Xg\";})(),(function fuck(){return \"ADy\";})(),(function fuck(){return \"ZVi\";})(),(" ascii
    $s2 = "n \"GJx\";})(),(function fuck(){return \"ZVi\";})(),(function fuck(){return \"UOe\";})(),(function fuck(){return \"IPu\";})(),(f" ascii
    $s3 = "uck(){return \"Fv\";})(),(function fuck(){return \"MUs\";})(),(function fuck(){return \"Xw\";})(),(function fuck(){return \"IPu" ascii
    $s4 = "n \"MBg\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"Xw\";})(),(function fuck(){return \"UOe\";})(),(fu" ascii
    $s5 = "q\";})(),(function fuck(){return \"Ug\";})(),(function fuck(){return \"Bz\";})(),(function fuck(){return \"Dc\";})(),(function f" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}