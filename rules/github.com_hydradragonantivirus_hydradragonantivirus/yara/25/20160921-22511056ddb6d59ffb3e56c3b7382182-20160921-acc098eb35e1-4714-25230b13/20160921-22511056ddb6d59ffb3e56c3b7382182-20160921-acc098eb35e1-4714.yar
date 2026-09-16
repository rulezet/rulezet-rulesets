rule _20160921_22511056ddb6d59ffb3e56c3b7382182_20160921_acc098eb35e1_4714 {
  meta:
    description = "datamaliciousorder - from files 20160921_22511056ddb6d59ffb3e56c3b7382182.js, 20160921_acc098eb35e159f33783b155bb8929cb.js, 20160921_e2cf0a7330632dcfdd75ef1c324289b4.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "1a5f7b2bfdf24defc0d363114441d0c0a0452fd599bf21d359b1b5f068dfc567"
    hash2       = "1f491f3a68df5684f7bb14dc15b8f6f3dea400dde990f144e6cf0792facdba6e"
    hash3       = "ad7238fc2ad12cca7ecf6bccdbe5df095519b23408e1a1f63f4ad19a50469d2e"

  strings:
    $s1 = " fuck(){return \"We\";})(),(function fuck(){return \"Xg\";})(),(function fuck(){return \"Fv\";})(),(function fuck(){return \"DWe" ascii
    $s2 = "tion fuck(){return \"Za\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"Yk\";})(),(function fuck(){return " ascii
    $s3 = "){return \"QTc\";})(),(function fuck(){return \"NKq\";})(),(function fuck(){return \"Ug\";})(),(function fuck(){return \"Bz\";})" ascii
    $s4 = " \"Fv\";})(),(function fuck(){return \"Zy\";})(),(function fuck(){return \"Ik\";})(),(function fuck(){return \"Fv\";})(),(functi" ascii
    $s5 = "n fuck(){return \"Yk\";})(),(function fuck(){return \"MUs\";})(),(function fuck(){return \"Pc\";})(),(function fuck(){return \"X" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}