rule _20160921_469953d9833167e141d9f086f1f41437_20160921_d4e094c14df4_5068 {
  meta:
    description = "datamaliciousorder - from files 20160921_469953d9833167e141d9f086f1f41437.js, 20160921_d4e094c14df45f61de0e1163f51e03e6.js, 20160921_dc73cfa7a33eb762f38614c69a95919d.js, 20160921_e53844f4bb18305322896332fbd017e8.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "e29808d818b8f5ea60d0baa8d6c3284d3673878f7f4309c5981ced86dc40c5f1"
    hash2       = "2877b2ace685858babd88dd0ef1659f49f21c3f8b907e5b3889ec46bf3a7104a"
    hash3       = "50e80269adbbca38f500219eaf7cec16f396b3d8a7c56d342b2e4839819ea598"
    hash4       = "b8484bab412a47fffb0a694f32ca5de3480841bd1c0806d0a7e6e86dfd21de6c"

  strings:
    $s1 = ")(),(function fuck(){return \"LGo\";})(),(function fuck(){return \"RAi\";})(),(function fuck(){return \"ADy\";})(),(function fuc" ascii
    $s2 = "eturn \"Np\";})(),(function fuck(){return \"LGo\";})(),(function fuck(){return \"UOe\";})(),(function fuck(){return \"UOe\";})()" ascii
    $s3 = "tion fuck(){return \"USf\";})(),(function fuck(){return \"IRn\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){retur" ascii
    $s4 = "k(){return \"LGo\";})(),(function fuck(){return \"IRn\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"Yb\"" ascii
    $s5 = "nction fuck(){return \"Vb\";})(),(function fuck(){return \"MOj\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){retu" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}