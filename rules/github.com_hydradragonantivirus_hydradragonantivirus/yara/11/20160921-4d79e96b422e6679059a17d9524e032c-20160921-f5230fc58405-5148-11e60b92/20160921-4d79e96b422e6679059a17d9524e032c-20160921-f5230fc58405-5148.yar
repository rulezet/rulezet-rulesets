rule _20160921_4d79e96b422e6679059a17d9524e032c_20160921_f5230fc58405_5148 {
  meta:
    description = "datamaliciousorder - from files 20160921_4d79e96b422e6679059a17d9524e032c.js, 20160921_f5230fc58405f25233bda6815654bd6e.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "d5794a16a28dba8e89768fa9195da33a7e28c3da5fc73a7789e7c04395f23f06"
    hash2       = "1a813dda7d0088c45bb00563ea79982995ec1337c805380117fe705f80c51c64"

  strings:
    $s1 = "ion fuck(){return \"UOe\";})(),(function fuck(){return \"UOe\";})(),(function fuck(){return \"Np\";})(),(function fuck(){return " ascii
    $s2 = "k(){return \"RAi\";})(),(function fuck(){return \"UOe\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"DRx" ascii
    $s3 = ")(),(function fuck(){return \"TTs\";})(),(function fuck(){return \"To\";})(),(function fuck(){return \"UXf\";})(),(function fuck" ascii
    $s4 = "nction fuck(){return \"Vb\";})(),(function fuck(){return \"UOe\";})(),(function fuck(){return \"RAi\";})(),(function fuck(){retu" ascii
    $s5 = "Vb\";})(),(function fuck(){return \"IRn\";})(),(function fuck(){return \"MBg\";})(),(function fuck(){return \"UOe\";})(),(functi" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}