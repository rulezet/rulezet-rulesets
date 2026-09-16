rule _20160921_03b650867a3952f7709688e58e8232f3_20160921_5230866e44ed_2204 {
  meta:
    description = "datamaliciousorder - from files 20160921_03b650867a3952f7709688e58e8232f3.js, 20160921_5230866e44eda4e054d929933fdfdae1.js, 20160921_63a82ecb2e4eb3b0dd878bbec885c469.js, 20160921_70b567ca258b3c505e14f3c712366f09.js, 20160921_ec2d2710e9217c2f295a4b410a623d5d.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "a775853212fe6663d7c077a64c0d4c851d4b7f261a6c0846b4552b556e12a5fe"
    hash2       = "4b11d10d6c2a935fa29f47c13ee54d426aac8d667f3bc2f79681ac7e4d365c76"
    hash3       = "0e9de62be8773f33e42da56c84c9c85d07f7c2616909543479f7803e6794a9ef"
    hash4       = "8cf06551c554a2db81fe1bf37b069b40e558f931913e7d2572bdd18b36f57c73"
    hash5       = "efabdabbb3a7d8e1d713826868acadadd9ab03b4cb57f3799d6add11f212fdd9"

  strings:
    $s1 = "w\";})(),(function fuck(){return \"IOs\";})(),(function fuck(){return \"EHo\";})(),(function fuck(){return \"Xw\";})(),(function" ascii
    $s2 = "urn \"IPu\";})(),(function fuck(){return \"Ug\";})(),(function fuck(){return \"DAa\";})(),(function fuck(){return \"RAi\";})(),(" ascii
    $s3 = "Df\";})(),(function fuck(){return \"We\";})(),(function fuck(){return \"Pc\";})(),(function fuck(){return \"Xw\";})(),(function " ascii
    $s4 = "n fuck(){return \"Mw\";})(),(function fuck(){return \"KVh\";})(),(function fuck(){return \"Xg\";})(),(function fuck(){return \"X" ascii
    $s5 = "(function fuck(){return \"XCr\";})(),(function fuck(){return \"Xw\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){r" ascii
    $s6 = "\";})(),(function fuck(){return \"XCr\";})(),(function fuck(){return \"Jg\";})(),(function fuck(){return \"Jo\";})(),(function f" ascii
    $s7 = "rn \"IPu\";})(),(function fuck(){return \"XFd\";})(),(function fuck(){return \"Et\";})(),(function fuck(){return \"Sx\";})(),(fu" ascii
    $s8 = "eturn \"Za\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"GJx\";})(),(function fuck(){return \"Vf\";})()," ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}