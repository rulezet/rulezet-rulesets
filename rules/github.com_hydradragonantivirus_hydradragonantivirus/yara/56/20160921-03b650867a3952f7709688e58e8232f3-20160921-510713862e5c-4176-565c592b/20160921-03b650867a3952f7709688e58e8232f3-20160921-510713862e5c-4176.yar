rule _20160921_03b650867a3952f7709688e58e8232f3_20160921_510713862e5c_4176 {
  meta:
    description = "datamaliciousorder - from files 20160921_03b650867a3952f7709688e58e8232f3.js, 20160921_510713862e5c8c05841e5272407127f3.js, 20160921_a160e4a385807ffcdde4f99a0c57b6b2.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "a775853212fe6663d7c077a64c0d4c851d4b7f261a6c0846b4552b556e12a5fe"
    hash2       = "9f9cd81d24cdba49fd83fed4aa0c3ce028729b44e223720bae200336b5992e5e"
    hash3       = "c3eeb2af6e453aec7ede2bba435e7dcf60f7497a94584d1908a2235d79c28a34"

  strings:
    $s1 = "ck(){return \"UXf\";})(),(function fuck(){return \"Jo\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"DRx" ascii
    $s2 = "(){return \"GWo\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"DRx\";})(),(function fuck(){return \"IPu\"" ascii
    $s3 = "n \"DRx\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"Wo\";})(),(function fuck(){return \"To\";})(),(fun" ascii
    $s4 = "uck(){return \"MBg\";})(),(function fuck(){return \"Vf\";})(),(function fuck(){return \"We\";})(),(function fuck(){return \"Dc\"" ascii
    $s5 = "unction fuck(){return \"OQr\";})(),(function fuck(){return \"Yk\";})(),(function fuck(){return \"QTc\";})(),(function fuck(){ret" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}