rule _20160921_38347709a1c3747cfb23ae60221ea7bf_20160921_511769d99fbe_3647 {
  meta:
    description = "datamaliciousorder - from files 20160921_38347709a1c3747cfb23ae60221ea7bf.js, 20160921_511769d99fbe4d59a2e55781fb0eb77c.js, 20160921_acea633b73985995ce9764bf94db0972.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "39473c48023f5000ce36bdc645860556dc6b5f3b0022f86190a49370f4633bbc"
    hash2       = "2f4a69b097fb3d0d29d7f041be11cd2e8af137bd0ed525674079a1b7de28c7fd"
    hash3       = "dd77df78b3a755b016a27bbcac8fe7c015ab04472e2ca2d2d9aa476befb3148a"

  strings:
    $s1 = " \"MBg\";})(),(function fuck(){return \"MBg\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"Oh\";})(),(fun" ascii
    $s2 = "\"UOe\";})(),(function fuck(){return \"ADy\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"DRx\";})(),(fun" ascii
    $s3 = "k(){return \"MUs\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"OQr\";})(),(function fuck(){return \"OQr" ascii
    $s4 = "ck(){return \"IPu\";})(),(function fuck(){return \"USf\";})(),(function fuck(){return \"ADy\";})(),(function fuck(){return \"UOe" ascii
    $s5 = "function fuck(){return \"IKv\";})(),(function fuck(){return \"USf\";})(),(function fuck(){return \"ADy\";})(),(function fuck(){r" ascii
    $s6 = "ion fuck(){return \"Za\";})(),(function fuck(){return \"Jg\";})(),(function fuck(){return \"Ug\";})(),(function fuck(){return \"" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}