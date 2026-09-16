rule _20160921_1e07803d7c44ae0b61b5ddf189c80675_20160921_460a913db46b_3484 {
  meta:
    description = "datamaliciousorder - from files 20160921_1e07803d7c44ae0b61b5ddf189c80675.js, 20160921_460a913db46b41c41035cc210ed5fba0.js, 20160921_abc9044816c2455dc24ac338746b6bd5.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "1a50e95e48071d391fd7544518c3c0394e9cde9051c76cf311992966b7414cc8"
    hash2       = "99bd08fbf869b4c9520d81d5b17512d87856474b8cf260494d0c88a47e0d37c9"
    hash3       = "2bb53920235afb1c2d16f013bc118d1df64065eefc10c1b2b9e7a4b133850850"

  strings:
    $s1 = "eturn \"XCr\";})(),(function fuck(){return \"Vf\";})(),(function fuck(){return \"EHo\";})(),(function fuck(){return \"IPu\";})()" ascii
    $s2 = "fuck(){return \"Jh\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"Cd\";})(),(function fuck(){return \"Za" ascii
    $s3 = "\"IPu\";})(),(function fuck(){return \"LGo\";})(),(function fuck(){return \"RAi\";})(),(function fuck(){return \"LGo\";})(),(fun" ascii
    $s4 = "tion fuck(){return \"Za\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"Ve\";})(),(function fuck(){return " ascii
    $s5 = "n \"ADy\";})(),(function fuck(){return \"Vb\";})(),(function fuck(){return \"IRn\";})(),(function fuck(){return \"MBg\";})(),(fu" ascii
    $s6 = "n \"USf\";})(),(function fuck(){return \"TTs\";})(),(function fuck(){return \"ADy\";})(),(function fuck(){return \"RAi\";})(),(f" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}