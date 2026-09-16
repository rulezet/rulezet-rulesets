rule _20160921_1664afae318573894e850f85ff412d64_20160921_9eb4e3262a9b_4500 {
  meta:
    description = "datamaliciousorder - from files 20160921_1664afae318573894e850f85ff412d64.js, 20160921_9eb4e3262a9bc5c5f03ba0b7b62a3347.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "c41fd157f38d62b8a8b91fe197ee0a409bd6fd7582b976184456d2447110138a"
    hash2       = "03bf8e47f97cab996cc7f2d8147659dc1143ccbe1fd09af6b8689379f7263407"

  strings:
    $s1 = ";})(),(function fuck(){return \"DRx\";})(),(function fuck(){return \"XHj\";})(),(function fuck(){return \"SUi\";})(),(function f" ascii
    $s2 = "nction fuck(){return \"Vf\";})(),(function fuck(){return \"SUi\";})(),(function fuck(){return \"MOj\";})(),(function fuck(){retu" ascii
    $s3 = "(){return \"RAi\";})(),(function fuck(){return \"MBg\";})(),(function fuck(){return \"Vb\";})(),(function fuck(){return \"LGo\";" ascii
    $s4 = "ction fuck(){return \"DRx\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"Vf\";})(),(function fuck(){retur" ascii
    $s5 = "ck(){return \"USf\";})(),(function fuck(){return \"Np\";})(),(function fuck(){return \"Xw\";})(),(function fuck(){return \"NKq\"" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}