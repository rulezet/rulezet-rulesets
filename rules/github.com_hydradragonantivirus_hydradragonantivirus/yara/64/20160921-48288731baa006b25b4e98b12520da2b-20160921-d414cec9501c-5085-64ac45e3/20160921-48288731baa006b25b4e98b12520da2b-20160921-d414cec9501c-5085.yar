rule _20160921_48288731baa006b25b4e98b12520da2b_20160921_d414cec9501c_5085 {
  meta:
    description = "datamaliciousorder - from files 20160921_48288731baa006b25b4e98b12520da2b.js, 20160921_d414cec9501c17802073a2f8f7b005c4.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "ce917015afcf31459cc47b8864f85394a756701f6338f6a2cbe079779c3ecd43"
    hash2       = "65e6cb34b6f46aaa1020cec9a648634a1eceb7e9d6ad0387fc939923e8236594"

  strings:
    $s1 = "ck(){return \"Za\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"Wo\";})(),(function fuck(){return \"UXf\"" ascii
    $s2 = "uck(){return \"Ug\";})(),(function fuck(){return \"SUi\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"MBg" ascii
    $s3 = "ion fuck(){return \"Dc\";})(),(function fuck(){return \"Hs\";})(),(function fuck(){return \"Xw\";})(),(function fuck(){return \"" ascii
    $s4 = "on fuck(){return \"IOs\";})(),(function fuck(){return \"Hs\";})(),(function fuck(){return \"MBg\";})(),(function fuck(){return " ascii
    $s5 = "fuck(){return \"XCr\";})(),(function fuck(){return \"Av\";})(),(function fuck(){return \"SUi\";})(),(function fuck(){return \"Xg" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}