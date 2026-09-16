rule _20160921_acea633b73985995ce9764bf94db0972_20160921_be4748da0160_5628 {
  meta:
    description = "datamaliciousorder - from files 20160921_acea633b73985995ce9764bf94db0972.js, 20160921_be4748da01602fdf2d9ffd03054028e4.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "dd77df78b3a755b016a27bbcac8fe7c015ab04472e2ca2d2d9aa476befb3148a"
    hash2       = "4847889a558b3e0b60d671ec5082e36330f771c8789f9ae89683bf49e7128616"

  strings:
    $s1 = "GJx\";})(),(function fuck(){return \"YAv\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"MBg\";})(),(funct" ascii
    $s2 = "rn \"Vb\";})(),(function fuck(){return \"YQt\";})(),(function fuck(){return \"IRn\";})(),(function fuck(){return \"MBg\";})(),(f" ascii
    $s3 = "ck(){return \"IPu\";})(),(function fuck(){return \"Xw\";})(),(function fuck(){return \"YAv\";})(),(function fuck(){return \"Pc\"" ascii
    $s4 = ",(function fuck(){return \"UOe\";})(),(function fuck(){return \"AUx\";})(),(function fuck(){return \"NKq\";})(),(function fuck()" ascii
    $s5 = "uck(){return \"MBg\";})(),(function fuck(){return \"LGo\";})(),(function fuck(){return \"GNm\";})(),(function fuck(){return \"AU" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}