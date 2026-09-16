rule _20160921_64060d97e498db57bf68dbb08be86bba_20160921_ee80dc6199fa_5315 {
  meta:
    description = "datamaliciousorder - from files 20160921_64060d97e498db57bf68dbb08be86bba.js, 20160921_ee80dc6199fa2bd2aea50402a233f984.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "30a02b9f75ed0112affe2c698cfdbe2ec2a5bc4d8248ac34ebe13e072bd212f0"
    hash2       = "b51d9165093e08385081a749ef6331a3556fe2739b6c8f85b62e7f6ec1b4f662"

  strings:
    $s1 = "\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"Hs\";})(),(function fuck(){return \"Np\";})(),(function f" ascii
    $s2 = "nction fuck(){return \"ADy\";})(),(function fuck(){return \"ADy\";})(),(function fuck(){return \"UOe\";})(),(function fuck(){ret" ascii
    $s3 = "(){return \"Ar\";})(),(function fuck(){return \"TTs\";})(),(function fuck(){return \"Hs\";})(),(function fuck(){return \"Np\";})" ascii
    $s4 = "UOe\";})(),(function fuck(){return \"Vb\";})(),(function fuck(){return \"Hs\";})(),(function fuck(){return \"USf\";})(),(functio" ascii
    $s5 = "Oj\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"DRx\";})(),(function fuck(){return \"IPu\";})(),(functi" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}