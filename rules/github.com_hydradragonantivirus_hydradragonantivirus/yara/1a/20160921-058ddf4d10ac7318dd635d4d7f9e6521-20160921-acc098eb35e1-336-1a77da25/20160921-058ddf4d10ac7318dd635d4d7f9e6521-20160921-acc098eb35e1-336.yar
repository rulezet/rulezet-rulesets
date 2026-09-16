rule _20160921_058ddf4d10ac7318dd635d4d7f9e6521_20160921_acc098eb35e1_336 {
  meta:
    description = "datamaliciousorder - from files 20160921_058ddf4d10ac7318dd635d4d7f9e6521.js, 20160921_acc098eb35e159f33783b155bb8929cb.js, 20160921_cda776f6c5cb6eec510c00d5294fbfae.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "beed60d53c1dc194e146ec112b43046bd7ea366584d59483d351cd57e1208385"
    hash2       = "1f491f3a68df5684f7bb14dc15b8f6f3dea400dde990f144e6cf0792facdba6e"
    hash3       = "064df16cff12584bccc68fb79fe80908e6edeb4ccf32c3c0b6a79b8b0424820c"

  strings:
    $s1  = "turn \"Cd\";})(),(function fuck(){return \"Np\";})(),(function fuck(){return \"RAi\";})(),(function fuck(){return \"NKq\";})(),(" ascii
    $s2  = "tion fuck(){return \"MBg\";})(),(function fuck(){return \"PDf\";})(),(function fuck(){return \"USf\";})(),(function fuck(){retur" ascii
    $s3  = "eturn \"LGo\";})(),(function fuck(){return \"PDf\";})(),(function fuck(){return \"Vb\";})(),(function fuck(){return \"GNm\";})()" ascii
    $s4  = "on fuck(){return \"Cd\";})(),(function fuck(){return \"LGo\";})(),(function fuck(){return \"USf\";})(),(function fuck(){return " ascii
    $s5  = "fuck(){return \"TTs\";})(),(function fuck(){return \"Np\";})(),(function fuck(){return \"UOe\";})(),(function fuck(){return \"PD" ascii
    $s6  = "k(){return \"RAi\";})(),(function fuck(){return \"TTs\";})(),(function fuck(){return \"YQt\";})(),(function fuck(){return \"Wo0" ascii
    $s7  = "on fuck(){return \"Np\";})(),(function fuck(){return \"Np\";})(),(function fuck(){return \"UOe\";})(),(function fuck(){return \"" ascii
    $s8  = "){return \"CTm\";})(),(function fuck(){return \"CTm\";})(),(function fuck(){return \"YQt\";})(),(function fuck(){return \"GWo\";" ascii
    $s9  = "ck(){return \"USf\";})(),(function fuck(){return \"GNm\";})(),(function fuck(){return \"ADy\";})(),(function fuck(){return \"IRn" ascii
    $s10 = "turn \"QTc\";})(),(function fuck(){return \"GNm\";})(),(function fuck(){return \"IRn\";})(),(function fuck(){return \"OQr\";})()" ascii
    $s11 = "fuck(){return \"RAi\";})(),(function fuck(){return \"RAi\";})(),(function fuck(){return \"UOe\";})(),(function fuck(){return \"G" ascii
    $s12 = ")(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"Oh\";})(),(function fuck(){return \"Oh\";})(),(function fuck(" ascii
    $s13 = "on fuck(){return \"RAi\";})(),(function fuck(){return \"GNm\";})(),(function fuck(){return \"USf\";})(),(function fuck(){return " ascii
    $s14 = " fuck(){return \"ADy\";})(),(function fuck(){return \"Vb\";})(),(function fuck(){return \"NKq\";})(),(function fuck(){return \"U" ascii
    $s15 = "nction fuck(){return \"Za\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"We\";})(),(function fuck(){retur" ascii
    $s16 = "ck(){return \"DRx\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"PDf\";})(),(function fuck(){return \"PDf" ascii
    $s17 = "),(function fuck(){return \"RAi\";})(),(function fuck(){return \"UOe\";})(),(function fuck(){return \"Cd\";})(),(function fuck()" ascii
    $s18 = "tion fuck(){return \"Hs\";})(),(function fuck(){return \"Ve\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return " ascii
    $s19 = ";})(),(function fuck(){return \"GNm\";})(),(function fuck(){return \"PDf\";})(),(function fuck(){return \"GNm\";})(),(function f" ascii
    $s20 = " fuck(){return \"MBg\";})(),(function fuck(){return \"UXf\";})(),(function fuck(){return \"Xg\";})(),(function fuck(){return \"V" ascii

  condition:
    (uint16(0) == 0x2f0a and (8 of them)
    ) or (all of them)
}