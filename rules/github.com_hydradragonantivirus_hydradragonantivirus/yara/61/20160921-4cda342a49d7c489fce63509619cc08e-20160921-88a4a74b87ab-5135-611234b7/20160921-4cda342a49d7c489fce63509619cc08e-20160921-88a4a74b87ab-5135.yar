rule _20160921_4cda342a49d7c489fce63509619cc08e_20160921_88a4a74b87ab_5135 {
  meta:
    description = "datamaliciousorder - from files 20160921_4cda342a49d7c489fce63509619cc08e.js, 20160921_88a4a74b87ab9fd3fb3dd307f9d7213d.js, 20160921_bd4d87f94769a02253ed6ac2e747557f.js, 20160921_dcd6ef8585af301daafce3419ba14724.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "cabf2bed3c4b1c46c86905c48d0ce38dc15e155546fd36ce4d681314485c6aeb"
    hash2       = "33ff531b193580829a3217137df52750b8df810994123bd1d02bfced3fa6c2ce"
    hash3       = "de567d209b0d4353173c2f3ae63037edd6f5695cc5edcdba1dba29b422d963ac"
    hash4       = "599a5b97cea2145a98305cb09031a146a6d64c54509328df8783368c3a3ba008"

  strings:
    $s1 = "(function fuck(){return \"IKv\";})(),(function fuck(){return \"USf\";})(),(function fuck(){return \"ADy\";})(),(function fuck(){" ascii
    $s2 = "ck(){return \"MUs\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"OQr\";})(),(function fuck(){return \"OQr" ascii
    $s3 = "uck(){return \"IPu\";})(),(function fuck(){return \"USf\";})(),(function fuck(){return \"ADy\";})(),(function fuck(){return \"UO" ascii
    $s4 = "n \"MBg\";})(),(function fuck(){return \"MBg\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"Oh\";})(),(fu" ascii
    $s5 = " \"UOe\";})(),(function fuck(){return \"ADy\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"DRx\";})(),(fu" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}