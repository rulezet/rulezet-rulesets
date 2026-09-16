rule _20160921_20daf816cda5af37e984359023f15db2_20160921_510713862e5c_4664 {
  meta:
    description = "datamaliciousorder - from files 20160921_20daf816cda5af37e984359023f15db2.js, 20160921_510713862e5c8c05841e5272407127f3.js, 20160921_fa89d54bd5a7a27defe09d5a56b5a881.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "a45ccf6470d4ee194ed220125c42c5ac5d7c4b8a46cce738c6d12e9cc0bafea8"
    hash2       = "9f9cd81d24cdba49fd83fed4aa0c3ce028729b44e223720bae200336b5992e5e"
    hash3       = "30f2a7c2562ef79254c8129be50246b9c41eb24f000c8cfbd0f4f8c28b49b00f"

  strings:
    $s1 = ";})(),(function fuck(){return \"XCr\";})(),(function fuck(){return \"Zy\";})(),(function fuck(){return \"Ik\";})(),(function fuc" ascii
    $s2 = "urn \"GWo\";})(),(function fuck(){return \"Jo\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"DRx\";})(),(" ascii
    $s3 = "rn \"MIl\";})(),(function fuck(){return \"To\";})(),(function fuck(){return \"AUx\";})(),(function fuck(){return \"MOj\";})(),(f" ascii
    $s4 = "on fuck(){return \"Sx\";})(),(function fuck(){return \"LGo\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return " ascii
    $s5 = "\"Vf\";})(),(function fuck(){return \"Ik\";})(),(function fuck(){return \"UOe\";})(),(function fuck(){return \"MBg\";})(),(funct" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}