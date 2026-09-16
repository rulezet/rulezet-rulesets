rule _20160921_abc9044816c2455dc24ac338746b6bd5_20160921_fa89d54bd5a7_4020 {
  meta:
    description = "datamaliciousorder - from files 20160921_abc9044816c2455dc24ac338746b6bd5.js, 20160921_fa89d54bd5a7a27defe09d5a56b5a881.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "2bb53920235afb1c2d16f013bc118d1df64065eefc10c1b2b9e7a4b133850850"
    hash2       = "30f2a7c2562ef79254c8129be50246b9c41eb24f000c8cfbd0f4f8c28b49b00f"

  strings:
    $s1 = "n fuck(){return \"Ve\";})(),(function fuck(){return \"Yk\";})(),(function fuck(){return \"Wo0\";})(),(function fuck(){return \"M" ascii
    $s2 = "on fuck(){return \"Hs\";})(),(function fuck(){return \"Jo\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"" ascii
    $s3 = "return \"ZWu\";})(),(function fuck(){return \"Cd\";})(),(function fuck(){return \"Fv\";})(),(function fuck(){return \"Np\";})()," ascii
    $s4 = "\"MBg\";})(),(function fuck(){return \"Vb\";})(),(function fuck(){return \"Hs\";})(),(function fuck(){return \"Hs\";})(),(functi" ascii
    $s5 = "return \"Hs\";})(),(function fuck(){return \"ADy\";})(),(function fuck(){return \"RAi\";})(),(function fuck(){return \"ADy\";})(" ascii
    $s6 = "tion fuck(){return \"IKv\";})(),(function fuck(){return \"LGo\";})(),(function fuck(){return \"Hs\";})(),(function fuck(){return" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}