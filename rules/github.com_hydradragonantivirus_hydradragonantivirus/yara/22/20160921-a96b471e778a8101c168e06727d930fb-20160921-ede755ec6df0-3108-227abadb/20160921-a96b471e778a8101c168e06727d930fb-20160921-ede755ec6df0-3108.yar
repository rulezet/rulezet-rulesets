rule _20160921_a96b471e778a8101c168e06727d930fb_20160921_ede755ec6df0_3108 {
  meta:
    description = "datamaliciousorder - from files 20160921_a96b471e778a8101c168e06727d930fb.js, 20160921_ede755ec6df0951d79fb3f792a6b28b8.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "f39378ed9c109b442c660bd7c383f0420860e3ac084eca6bb2fd789ead573a49"
    hash2       = "24831eade0fe1d3e87c174bc2c80b113a66f4b5da6235749feba09a377913e7a"

  strings:
    $s1 = "turn \"MIl\";})(),(function fuck(){return \"Sx\";})(),(function fuck(){return \"DRx\";})(),(function fuck(){return \"ZLd\";})()," ascii
    $s2 = "unction fuck(){return \"LGo\";})(),(function fuck(){return \"YQt\";})(),(function fuck(){return \"Np\";})(),(function fuck(){ret" ascii
    $s3 = "),(function fuck(){return \"CCb\";})(),(function fuck(){return \"Mw\";})(),(function fuck(){return \"Np\";})(),(function fuck(){" ascii
    $s4 = "on fuck(){return \"YQt\";})(),(function fuck(){return \"GNm\";})(),(function fuck(){return \"NKq\";})(),(function fuck(){return " ascii
    $s5 = "n fuck(){return \"Ot\";})(),(function fuck(){return \"Sx\";})(),(function fuck(){return \"ADy\";})(),(function fuck(){return \"D" ascii
    $s6 = "k(){return \"KVh\";})(),(function fuck(){return \"YQt\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"DRx" ascii
    $s7 = " \"DRx\";})(),(function fuck(){return \"Zy\";})(),(function fuck(){return \"MUs\";})(),(function fuck(){return \"IPu\";})(),(fun" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}