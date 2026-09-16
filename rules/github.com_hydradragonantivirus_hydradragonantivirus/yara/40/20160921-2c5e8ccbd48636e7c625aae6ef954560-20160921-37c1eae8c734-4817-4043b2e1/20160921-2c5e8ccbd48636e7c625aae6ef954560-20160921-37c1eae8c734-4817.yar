rule _20160921_2c5e8ccbd48636e7c625aae6ef954560_20160921_37c1eae8c734_4817 {
  meta:
    description = "datamaliciousorder - from files 20160921_2c5e8ccbd48636e7c625aae6ef954560.js, 20160921_37c1eae8c73482d7ccd62bb1c25f74b0.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "70244ca5fa124af09b1f94729567c09dbc52c05035ee7d20cbe87d35e1fe63c8"
    hash2       = "8e724c0f7c8722eec82dd0f37b13b38ab5c357aeccb2cc6c36efae80bae66a8a"

  strings:
    $s1 = "on fuck(){return \"Oh\";})(),(function fuck(){return \"Ug\";})(),(function fuck(){return \"KVh\";})(),(function fuck(){return \"" ascii
    $s2 = "rn \"YQt\";})(),(function fuck(){return \"Sx\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"DRx\";})(),(f" ascii
    $s3 = "Oe\";})(),(function fuck(){return \"TTs\";})(),(function fuck(){return \"AUx\";})(),(function fuck(){return \"Ug\";})(),(functio" ascii
    $s4 = "(){return \"DRx\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"YQt\";})(),(function fuck(){return \"QTc\"" ascii
    $s5 = ")(),(function fuck(){return \"OQr\";})(),(function fuck(){return \"XFd\";})(),(function fuck(){return \"SUi\";})(),(function fuc" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}