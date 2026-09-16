rule _20160921_7f682825ca903be9931443996a6639e7_20160921_f7fa978ba93c_967 {
  meta:
    description = "datamaliciousorder - from files 20160921_7f682825ca903be9931443996a6639e7.js, 20160921_f7fa978ba93ca4504da33fc02cbf7f53.js, 20160921_f80c41f35464b4c1cc71c3a8431a6e96.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "0702db471409264d1d764fadd3401cdedc4b3ca7166d99d61893fad5007d7f03"
    hash2       = "8c8d20603b0870465254e9f226f52f020b5b1d986c61571e7a3097b32ea728e0"
    hash3       = "8186d069d8ec2c8754bba46343500f71eff6d1d47a5ecb2ca82a097bf5b41dc3"

  strings:
    $s1  = "urn \"YQt\";})(),(function fuck(){return \"ADy\";})(),(function fuck(){return \"IRn\";})(),(function fuck(){return \"MBg\";})()," ascii
    $s2  = "fuck(){return \"MBg\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"Xw\";})(),(function fuck(){return \"YQ" ascii
    $s3  = "unction fuck(){return \"Vb\";})(),(function fuck(){return \"GNm\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){ret" ascii
    $s4  = "IPu\";})(),(function fuck(){return \"GJx\";})(),(function fuck(){return \"SUi\";})(),(function fuck(){return \"USf\";})(),(funct" ascii
    $s5  = "u\";})(),(function fuck(){return \"Xw\";})(),(function fuck(){return \"SUi\";})(),(function fuck(){return \"Xg\";})(),(function " ascii
    $s6  = "turn \"Ai\";})(),(function fuck(){return \"FJs\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"MBg\";})()," ascii
    $s7  = "ck(){return \"LGo\";})(),(function fuck(){return \"LGo\";})(),(function fuck(){return \"AUx\";})(),(function fuck(){return \"NKq" ascii
    $s8  = "rn \"Za\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"XFd\";})(),(function fuck(){return \"ZLd\";})(),(f" ascii
    $s9  = "){return \"Za\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"ZWu\";})(),(function fuck(){return \"EHo\";}" ascii
    $s10 = "ion fuck(){return \"Za\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"MIl\";})(),(function fuck(){return " ascii
    $s11 = "\";})(),(function fuck(){return \"LLv\";})(),(function fuck(){return \"ZLd\";})(),(function fuck(){return \"ZWu\";})(),(function" ascii
    $s12 = ")(),(function fuck(){return \"ZLd\";})(),(function fuck(){return \"EHo\";})(),(function fuck(){return \"UOe\";})(),(function fuc" ascii
    $s13 = "eturn \"Np\";})(),(function fuck(){return \"IRn\";})(),(function fuck(){return \"MBg\";})(),(function fuck(){return \"AUx\";})()" ascii
    $s14 = " fuck(){return \"Xw\";})(),(function fuck(){return \"GJx\";})(),(function fuck(){return \"Za\";})(),(function fuck(){return \"Xw" ascii
    $s15 = "function fuck(){return \"Oh\";})(),(function fuck(){return \"XHj\";})(),(function fuck(){return \"Xw\";})(),(function fuck(){ret" ascii
    $s16 = "return \"CCb\";})(),(function fuck(){return \"Jh\";})(),(function fuck(){return \"ADy\";})(),(function fuck(){return \"IPu\";})(" ascii
    $s17 = "ck(){return \"Ai\";})(),(function fuck(){return \"Zy\";})(),(function fuck(){return \"Sx\";})(),(function fuck(){return \"IPu\";" ascii
    $s18 = ",(function fuck(){return \"Fv\";})(),(function fuck(){return \"Xg\";})(),(function fuck(){return \"Xw\";})(),(function fuck(){re" ascii
    $s19 = "n \"Wo\";})(),(function fuck(){return \"GJx\";})(),(function fuck(){return \"MUs\";})(),(function fuck(){return \"Np\";})(),(fun" ascii
    $s20 = ")(),(function fuck(){return \"XHj\";})(),(function fuck(){return \"QTc\";})(),(function fuck(){return \"Xw\";})(),(function fuck" ascii

  condition:
    (uint16(0) == 0x2f0a and (8 of them)
    ) or (all of them)
}