rule _20160921_4d79e96b422e6679059a17d9524e032c_20160921_57d7efd40780_5149 {
  meta:
    description = "datamaliciousorder - from files 20160921_4d79e96b422e6679059a17d9524e032c.js, 20160921_57d7efd4078096b801e379ee02f0feec.js, 20160921_acc098eb35e159f33783b155bb8929cb.js, 20160921_b04f9fe7316d0e86c0046e130e905e37.js, 20160921_e01bb59eb24d1686f9e2aeb1c9237853.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "d5794a16a28dba8e89768fa9195da33a7e28c3da5fc73a7789e7c04395f23f06"
    hash2       = "e568760a55d343665c530313749711c3424bfd35c792b1a8b1d5ad6fa004c9a6"
    hash3       = "1f491f3a68df5684f7bb14dc15b8f6f3dea400dde990f144e6cf0792facdba6e"
    hash4       = "58df336ac7568c9f52fedec5d0b900480491f3e65f56c23426010ec745a6bddd"
    hash5       = "6f5c056ecbe8fe7bc86b4862d32e261ec2bc26cff4b18206988fdb1c7059557c"

  strings:
    $s1 = "unction fuck(){return \"IPu\";})(),(function fuck(){return \"Vf\";})(),(function fuck(){return \"XCr\";})(),(function fuck(){ret" ascii
    $s2 = "(){return \"UXf\";})(),(function fuck(){return \"PDf\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"DRx\"" ascii
    $s3 = "ction fuck(){return \"DRx\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"Hs\";})(),(function fuck(){retur" ascii
    $s4 = "){return \"CCb\";})(),(function fuck(){return \"MUs\";})(),(function fuck(){return \"Cd\";})(),(function fuck(){return \"IPu\";}" ascii
    $s5 = "\"IOs\";})(),(function fuck(){return \"Fv\";})(),(function fuck(){return \"TTs\";})(),(function fuck(){return \"To\";})(),(funct" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}