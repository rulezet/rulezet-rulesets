rule _20160921_6a795b29889480550a8440815b06fa7d_20160921_d0ae6acc5cc4_3872 {
  meta:
    description = "datamaliciousorder - from files 20160921_6a795b29889480550a8440815b06fa7d.js, 20160921_d0ae6acc5cc4f52f8d5df0b47ef8659a.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "fb5890246703edf23742bd2e821c50d1610d87dc3d17ff4909414fae3bd26d96"
    hash2       = "8cde265a6a44d9e9f86f351959c030a86800d101b5b5ca057ac1cdc5c5a1e38d"

  strings:
    $s1 = ",(function fuck(){return \"To\";})(),(function fuck(){return \"Wo\";})(),(function fuck(){return \"Av\";})(),(function fuck(){re" ascii
    $s2 = "r\";})(),(function fuck(){return \"Qh\";})(),(function fuck(){return \"Xg\";})(),(function fuck(){return \"DRx\";})(),(function " ascii
    $s3 = "return \"Ot\";})(),(function fuck(){return \"Xg\";})(),(function fuck(){return \"DRx\";})(),(function fuck(){return \"MIl\";})()" ascii
    $s4 = "){return \"ZVi\";})(),(function fuck(){return \"UOe\";})(),(function fuck(){return \"DRx\";})(),(function fuck(){return \"GJx\";" ascii
    $s5 = "Jo\";})(),(function fuck(){return \"DRx\";})(),(function fuck(){return \"DWe\";})(),(function fuck(){return \"Ot\";})(),(functio" ascii
    $s6 = "nction fuck(){return \"IOs\";})(),(function fuck(){return \"Hs\";})(),(function fuck(){return \"DRx\";})(),(function fuck(){retu" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}