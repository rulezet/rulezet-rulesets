rule _20160921_105b4651b7160ca47c8bc86d4da31c43_20160921_65ff2a70ce98_4395 {
  meta:
    description = "datamaliciousorder - from files 20160921_105b4651b7160ca47c8bc86d4da31c43.js, 20160921_65ff2a70ce98d58243fbbdf4849b9c40.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "8e64d089e7076541ade19a5701fb8571545dde4a6c002b31df5fef02095005f7"
    hash2       = "4be01014513bc9c23e14a62953fb7d9f955467208a844109b10c685b1f9c4f29"

  strings:
    $s1 = "ck(){return \"USf\";})(),(function fuck(){return \"LGo\";})(),(function fuck(){return \"RAi\";})(),(function fuck(){return \"IPu" ascii
    $s2 = "\"IPu\";})(),(function fuck(){return \"MBg\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"LGo\";})(),(fun" ascii
    $s3 = " \"USf\";})(),(function fuck(){return \"LGo\";})(),(function fuck(){return \"RAi\";})(),(function fuck(){return \"NKq\";})(),(fu" ascii
    $s4 = "n fuck(){return \"YQt\";})(),(function fuck(){return \"Jg\";})(),(function fuck(){return \"DRx\";})(),(function fuck(){return \"" ascii
    $s5 = "eturn \"Xw\";})(),(function fuck(){return \"LLv\";})(),(function fuck(){return \"DHd\";})(),(function fuck(){return \"Xw\";})()," ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}