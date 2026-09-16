rule _20160921_262709d34b477380050375a3b5b2833b_20160921_4fa304d7c11d_4753 {
  meta:
    description = "datamaliciousorder - from files 20160921_262709d34b477380050375a3b5b2833b.js, 20160921_4fa304d7c11deb5fb9cd6514d5a983de.js, 20160921_b714100d69b955de920a302ff8bef7db.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "2738de24af2af834f5ce43b4e99137d47cd1993ec0b6dc3c1071deb99efcd62c"
    hash2       = "cef5a1e67f57d9f24065ff0145644e0185df6abc29113310c6782b30e0a9236b"
    hash3       = "fc43d54db3c24d6f7ce2d47a45ffcd0768d5cfe90e405322e477be98fe4a8170"

  strings:
    $s1 = "){return \"Hs\";})(),(function fuck(){return \"Hs\";})(),(function fuck(){return \"RAi\";})(),(function fuck(){return \"NKq\";})" ascii
    $s2 = "eturn \"Vb\";})(),(function fuck(){return \"UOe\";})(),(function fuck(){return \"IRn\";})(),(function fuck(){return \"MBg\";})()" ascii
    $s3 = "ion fuck(){return \"IPu\";})(),(function fuck(){return \"Np\";})(),(function fuck(){return \"RAi\";})(),(function fuck(){return " ascii
    $s4 = "k(){return \"Jo\";})(),(function fuck(){return \"LGo\";})(),(function fuck(){return \"Hs\";})(),(function fuck(){return \"LGo\";" ascii
    $s5 = " fuck(){return \"TTs\";})(),(function fuck(){return \"LGo\";})(),(function fuck(){return \"Vb\";})(),(function fuck(){return \"J" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}