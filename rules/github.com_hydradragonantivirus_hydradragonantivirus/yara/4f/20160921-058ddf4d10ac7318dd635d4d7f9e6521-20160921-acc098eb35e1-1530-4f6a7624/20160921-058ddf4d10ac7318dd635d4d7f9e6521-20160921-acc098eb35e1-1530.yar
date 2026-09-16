rule _20160921_058ddf4d10ac7318dd635d4d7f9e6521_20160921_acc098eb35e1_1530 {
  meta:
    description = "datamaliciousorder - from files 20160921_058ddf4d10ac7318dd635d4d7f9e6521.js, 20160921_acc098eb35e159f33783b155bb8929cb.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "beed60d53c1dc194e146ec112b43046bd7ea366584d59483d351cd57e1208385"
    hash2       = "1f491f3a68df5684f7bb14dc15b8f6f3dea400dde990f144e6cf0792facdba6e"

  strings:
    $s1  = ")(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"GJx\";})(),(function fuck(){return \"Mw\";})(),(function fuck" ascii
    $s2  = "(){return \"IPu\";})(),(function fuck(){return \"Ug\";})(),(function fuck(){return \"Bz\";})(),(function fuck(){return \"IPu\";}" ascii
    $s3  = "k(){return \"Oh\";})(),(function fuck(){return \"Fv\";})(),(function fuck(){return \"USf\";})(),(function fuck(){return \"IRn\";" ascii
    $s4  = "urn \"ADy\";})(),(function fuck(){return \"TTs\";})(),(function fuck(){return \"Qh\";})(),(function fuck(){return \"Zy\";})(),(f" ascii
    $s5  = "unction fuck(){return \"Yk\";})(),(function fuck(){return \"AUx\";})(),(function fuck(){return \"LGo\";})(),(function fuck(){ret" ascii
    $s6  = "tion fuck(){return \"IPu\";})(),(function fuck(){return \"Vf\";})(),(function fuck(){return \"EHo\";})(),(function fuck(){return" ascii
    $s7  = "r\";})(),(function fuck(){return \"Nm\";})(),(function fuck(){return \"ZWu\";})(),(function fuck(){return \"FJs\";})(),(function" ascii
    $s8  = "){return \"YAv\";})(),(function fuck(){return \"USf\";})(),(function fuck(){return \"NKq\";})(),(function fuck(){return \"IPu\";" ascii
    $s9  = "on fuck(){return \"XFd\";})(),(function fuck(){return \"Ve\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return " ascii
    $s10 = "(function fuck(){return \"IPu\";})(),(function fuck(){return \"Et\";})(),(function fuck(){return \"Na\";})(),(function fuck(){re" ascii
    $s11 = " fuck(){return \"SUi\";})(),(function fuck(){return \"RAi\";})(),(function fuck(){return \"IRn\";})(),(function fuck(){return \"" ascii
    $s12 = "rn \"OPz\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"LGo\";})(),(function fuck(){return \"MOj\";})(),(" ascii

  condition:
    (uint16(0) == 0x2f0a and (8 of them)
    ) or (all of them)
}