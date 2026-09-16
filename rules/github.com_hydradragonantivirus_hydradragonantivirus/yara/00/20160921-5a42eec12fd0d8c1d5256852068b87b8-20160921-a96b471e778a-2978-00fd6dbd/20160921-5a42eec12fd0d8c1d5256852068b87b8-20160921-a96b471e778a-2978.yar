rule _20160921_5a42eec12fd0d8c1d5256852068b87b8_20160921_a96b471e778a_2978 {
  meta:
    description = "datamaliciousorder - from files 20160921_5a42eec12fd0d8c1d5256852068b87b8.js, 20160921_a96b471e778a8101c168e06727d930fb.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "54a7451a184fd8afa3cac9d787d5f83abeb8fecd14d9f136cff135e9f0d849e0"
    hash2       = "f39378ed9c109b442c660bd7c383f0420860e3ac084eca6bb2fd789ead573a49"

  strings:
    $s1 = "function fuck(){return \"CCb\";})(),(function fuck(){return \"Za\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){re" ascii
    $s2 = "eturn \"MBg\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"Oh\";})(),(function fuck(){return \"DWe\";})()" ascii
    $s3 = "urn \"TTs\";})(),(function fuck(){return \"LGo\";})(),(function fuck(){return \"USf\";})(),(function fuck(){return \"YQt\";})()," ascii
    $s4 = "tion fuck(){return \"OQr\";})(),(function fuck(){return \"Wo0\";})(),(function fuck(){return \"CCb\";})(),(function fuck(){retur" ascii
    $s5 = "rn \"IPu\";})(),(function fuck(){return \"Oh\";})(),(function fuck(){return \"Ve\";})(),(function fuck(){return \"Xg\";})(),(fun" ascii
    $s6 = "uck(){return \"Za\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"Wo\";})(),(function fuck(){return \"PDf" ascii
    $s7 = "\";})(),(function fuck(){return \"Np\";})(),(function fuck(){return \"TTs\";})(),(function fuck(){return \"Et\";})(),(function f" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}