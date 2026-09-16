rule _20160921_acc098eb35e159f33783b155bb8929cb_20160921_ce3c0604d52e_5626 {
  meta:
    description = "datamaliciousorder - from files 20160921_acc098eb35e159f33783b155bb8929cb.js, 20160921_ce3c0604d52e9dc9119cefedfee34385.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "1f491f3a68df5684f7bb14dc15b8f6f3dea400dde990f144e6cf0792facdba6e"
    hash2       = "27a20a400d7aa13737d230acf36a2170494c7da92e72552775d19562ba331fdc"

  strings:
    $s1 = "eturn \"IPu\";})(),(function fuck(){return \"Xw\";})(),(function fuck(){return \"DHd\";})(),(function fuck(){return \"AUx\";})()" ascii
    $s2 = "on fuck(){return \"MBg\";})(),(function fuck(){return \"IKv\";})(),(function fuck(){return \"UOe\";})(),(function fuck(){return " ascii
    $s3 = "ction fuck(){return \"UOe\";})(),(function fuck(){return \"MBg\";})(),(function fuck(){return \"Oh\";})(),(function fuck(){retur" ascii
    $s4 = "(){return \"IPu\";})(),(function fuck(){return \"Vf\";})(),(function fuck(){return \"ZLd\";})(),(function fuck(){return \"Sx\";}" ascii
    $s5 = "uck(){return \"IPu\";})(),(function fuck(){return \"Za\";})(),(function fuck(){return \"Xg\";})(),(function fuck(){return \"Fv\"" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}