rule _20160921_69a85efe2b4b34254269f0f82213bf2c_20160921_be8454f98b5a_5348 {
  meta:
    description = "datamaliciousorder - from files 20160921_69a85efe2b4b34254269f0f82213bf2c.js, 20160921_be8454f98b5a24b3ec56590bd13ee274.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "8def27dca1738a7df5978549903a2c809fcb8a8d158e5de122afc54ad2dd3dea"
    hash2       = "984696d2831d222abf66218ad54b440a2fd79bd47a7f1493a197576207321839"

  strings:
    $s1 = "})(),(function fuck(){return \"DRx\";})(),(function fuck(){return \"ZLd\";})(),(function fuck(){return \"Ot\";})(),(function fuc" ascii
    $s2 = "urn \"YAv\";})(),(function fuck(){return \"ADy\";})(),(function fuck(){return \"TTs\";})(),(function fuck(){return \"XCr\";})()," ascii
    $s3 = "unction fuck(){return \"TTs\";})(),(function fuck(){return \"ZLd\";})(),(function fuck(){return \"IOs\";})(),(function fuck(){re" ascii
    $s4 = "fuck(){return \"AUx\";})(),(function fuck(){return \"UOe\";})(),(function fuck(){return \"USf\";})(),(function fuck(){return \"I" ascii
    $s5 = "ion fuck(){return \"IRn\";})(),(function fuck(){return \"OQr\";})(),(function fuck(){return \"MIl\";})(),(function fuck(){return" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}