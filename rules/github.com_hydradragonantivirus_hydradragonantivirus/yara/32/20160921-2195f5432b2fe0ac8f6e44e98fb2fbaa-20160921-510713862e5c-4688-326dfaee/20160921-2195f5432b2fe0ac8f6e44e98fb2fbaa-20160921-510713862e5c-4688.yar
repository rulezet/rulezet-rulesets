rule _20160921_2195f5432b2fe0ac8f6e44e98fb2fbaa_20160921_510713862e5c_4688 {
  meta:
    description = "datamaliciousorder - from files 20160921_2195f5432b2fe0ac8f6e44e98fb2fbaa.js, 20160921_510713862e5c8c05841e5272407127f3.js, 20160921_5c25506bc44b50a0c8028dec6521139d.js, 20160921_7dec24f022af3c1ffe46748172dd6cad.js, 20160921_a160e4a385807ffcdde4f99a0c57b6b2.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "8753bd153b88da9a4351b5d6a0111d7af66a0f18e8b8a42beee11ad2916dc183"
    hash2       = "9f9cd81d24cdba49fd83fed4aa0c3ce028729b44e223720bae200336b5992e5e"
    hash3       = "b6178db9a292199c6992547ad654bf7056fa7f33310f29988e468f0cad5ed707"
    hash4       = "402e919998fdba69cb3992879db4f947916245c38915db643643952fa450e947"
    hash5       = "c3eeb2af6e453aec7ede2bba435e7dcf60f7497a94584d1908a2235d79c28a34"

  strings:
    $s1 = ";})(),(function fuck(){return \"CCb\";})(),(function fuck(){return \"Fv\";})(),(function fuck(){return \"DRx\";})(),(function fu" ascii
    $s2 = "n fuck(){return \"MUs\";})(),(function fuck(){return \"MOj\";})(),(function fuck(){return \"NKq\";})(),(function fuck(){return " ascii
    $s3 = ")(),(function fuck(){return \"SUi\";})(),(function fuck(){return \"LGo\";})(),(function fuck(){return \"IPu\";})(),(function fuc" ascii
    $s4 = "eturn \"XHj\";})(),(function fuck(){return \"GJx\";})(),(function fuck(){return \"ZVi\";})(),(function fuck(){return \"Jo\";})()" ascii
    $s5 = "turn \"DRx\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"Ot\";})(),(function fuck(){return \"XCr\";})()," ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}