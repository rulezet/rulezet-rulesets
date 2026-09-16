rule _20160921_5230866e44eda4e054d929933fdfdae1_20160921_63a82ecb2e4e_155 {
  meta:
    description = "datamaliciousorder - from files 20160921_5230866e44eda4e054d929933fdfdae1.js, 20160921_63a82ecb2e4eb3b0dd878bbec885c469.js, 20160921_70b567ca258b3c505e14f3c712366f09.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "4b11d10d6c2a935fa29f47c13ee54d426aac8d667f3bc2f79681ac7e4d365c76"
    hash2       = "0e9de62be8773f33e42da56c84c9c85d07f7c2616909543479f7803e6794a9ef"
    hash3       = "8cf06551c554a2db81fe1bf37b069b40e558f931913e7d2572bdd18b36f57c73"

  strings:
    $s1  = "})(),(function fuck(){return \"Xw\";})(),(function fuck(){return \"OPz\";})(),(function fuck(){return \"Wo0\";})(),(function fuc" ascii
    $s2  = ";})(),(function fuck(){return \"Fv\";})(),(function fuck(){return \"IOs\";})(),(function fuck(){return \"Pc\";})(),(function fuc" ascii
    $s3  = "rn \"Yk\";})(),(function fuck(){return \"CCb\";})(),(function fuck(){return \"Av\";})(),(function fuck(){return \"IPu\";})(),(fu" ascii
    $s4  = "nction fuck(){return \"IPu\";})(),(function fuck(){return \"Ot\";})(),(function fuck(){return \"AUx\";})(),(function fuck(){retu" ascii
    $s5  = "unction fuck(){return \"IPu\";})(),(function fuck(){return \"Ug\";})(),(function fuck(){return \"ZLd\";})(),(function fuck(){ret" ascii
    $s6  = ")(),(function fuck(){return \"Wo0\";})(),(function fuck(){return \"Vb\";})(),(function fuck(){return \"IPu\";})(),(function fuck" ascii
    $s7  = "n fuck(){return \"Za\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"Ve\";})(),(function fuck(){return \"A" ascii
    $s8  = "(function fuck(){return \"Xw\";})(),(function fuck(){return \"XCr\";})(),(function fuck(){return \"Xw\";})(),(function fuck(){re" ascii
    $s9  = "){return \"IPu\";})(),(function fuck(){return \"XCr\";})(),(function fuck(){return \"CCb\";})(),(function fuck(){return \"SUi\";" ascii
    $s10 = "fuck(){return \"IPu\";})(),(function fuck(){return \"Xw\";})(),(function fuck(){return \"Wo\";})(),(function fuck(){return \"EHo" ascii
    $s11 = "unction fuck(){return \"XHj\";})(),(function fuck(){return \"AUx\";})(),(function fuck(){return \"YAv\";})(),(function fuck(){re" ascii
    $s12 = "on fuck(){return \"Za\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"Ve\";})(),(function fuck(){return \"" ascii
    $s13 = "uck(){return \"Za\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"Oh\";})(),(function fuck(){return \"Zy\"" ascii
    $s14 = "eturn \"Za\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"Ai\";})(),(function fuck(){return \"MIl\";})()," ascii
    $s15 = "),(function fuck(){return \"KVh\";})(),(function fuck(){return \"ZLd\";})(),(function fuck(){return \"Xw\";})(),(function fuck()" ascii
    $s16 = " \"Xw\";})(),(function fuck(){return \"XHj\";})(),(function fuck(){return \"FJs\";})(),(function fuck(){return \"Za\";})(),(func" ascii
    $s17 = "ction fuck(){return \"Ar\";})(),(function fuck(){return \"Fv\";})(),(function fuck(){return \"Xw\";})(),(function fuck(){return " ascii
    $s18 = "fuck(){return \"IPu\";})(),(function fuck(){return \"Xw\";})(),(function fuck(){return \"Xg\";})(),(function fuck(){return \"UXf" ascii
    $s19 = "k(){return \"Fv\";})(),(function fuck(){return \"Za\";})(),(function fuck(){return \"Xg\";})(),(function fuck(){return \"Ik\";})" ascii
    $s20 = "uck(){return \"USf\";})(),(function fuck(){return \"LGo\";})(),(function fuck(){return \"Pc\";})(),(function fuck(){return \"Xg" ascii

  condition:
    (uint16(0) == 0x2f0a and (8 of them)
    ) or (all of them)
}