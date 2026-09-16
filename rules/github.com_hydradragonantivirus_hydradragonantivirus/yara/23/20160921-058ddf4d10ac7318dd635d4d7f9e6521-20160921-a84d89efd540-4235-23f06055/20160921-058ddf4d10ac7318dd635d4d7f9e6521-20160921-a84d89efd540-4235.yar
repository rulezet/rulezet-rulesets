rule _20160921_058ddf4d10ac7318dd635d4d7f9e6521_20160921_a84d89efd540_4235 {
  meta:
    description = "datamaliciousorder - from files 20160921_058ddf4d10ac7318dd635d4d7f9e6521.js, 20160921_a84d89efd5400c906c1132a56b0ef679.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "beed60d53c1dc194e146ec112b43046bd7ea366584d59483d351cd57e1208385"
    hash2       = "f3cfecdabdf17d9af410d0fee7ec88844bc361668aca1a114832bd3e515d3456"

  strings:
    $s1 = "\"ZVi\";})(),(function fuck(){return \"IRn\";})(),(function fuck(){return \"MBg\";})(),(function fuck(){return \"DWe\";})(),(fun" ascii
    $s2 = "ck(){return \"TTs\";})(),(function fuck(){return \"Nm\";})(),(function fuck(){return \"UXf\";})(),(function fuck(){return \"IPu" ascii
    $s3 = "on fuck(){return \"IPu\";})(),(function fuck(){return \"YQt\";})(),(function fuck(){return \"Ve\";})(),(function fuck(){return " ascii
    $s4 = "eturn \"GWo\";})(),(function fuck(){return \"Ik\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"DRx\";})()" ascii
    $s5 = ")(),(function fuck(){return \"MBg\";})(),(function fuck(){return \"Hs\";})(),(function fuck(){return \"YAv\";})(),(function fuck" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}