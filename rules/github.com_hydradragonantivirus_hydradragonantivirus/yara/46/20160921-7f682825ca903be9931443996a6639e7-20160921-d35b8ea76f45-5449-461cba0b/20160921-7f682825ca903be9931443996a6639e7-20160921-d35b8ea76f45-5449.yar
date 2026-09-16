rule _20160921_7f682825ca903be9931443996a6639e7_20160921_d35b8ea76f45_5449 {
  meta:
    description = "datamaliciousorder - from files 20160921_7f682825ca903be9931443996a6639e7.js, 20160921_d35b8ea76f45dbc35f302f0ac5357655.js, 20160921_f80c41f35464b4c1cc71c3a8431a6e96.js, 20160921_fa89d54bd5a7a27defe09d5a56b5a881.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "0702db471409264d1d764fadd3401cdedc4b3ca7166d99d61893fad5007d7f03"
    hash2       = "9dcc5774827243903cab74a4e9a77a6ec68f90a8c6ce60869e9bc7d13bcac921"
    hash3       = "8186d069d8ec2c8754bba46343500f71eff6d1d47a5ecb2ca82a097bf5b41dc3"
    hash4       = "30f2a7c2562ef79254c8129be50246b9c41eb24f000c8cfbd0f4f8c28b49b00f"

  strings:
    $s1 = " fuck(){return \"MUs\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"OQr\";})(),(function fuck(){return \"" ascii
    $s2 = "urn \"UOe\";})(),(function fuck(){return \"ADy\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"DRx\";})()," ascii
    $s3 = "(),(function fuck(){return \"IKv\";})(),(function fuck(){return \"USf\";})(),(function fuck(){return \"ADy\";})(),(function fuck" ascii
    $s4 = "turn \"MBg\";})(),(function fuck(){return \"MBg\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"Oh\";})()," ascii
    $s5 = "n fuck(){return \"IPu\";})(),(function fuck(){return \"USf\";})(),(function fuck(){return \"ADy\";})(),(function fuck(){return " ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}