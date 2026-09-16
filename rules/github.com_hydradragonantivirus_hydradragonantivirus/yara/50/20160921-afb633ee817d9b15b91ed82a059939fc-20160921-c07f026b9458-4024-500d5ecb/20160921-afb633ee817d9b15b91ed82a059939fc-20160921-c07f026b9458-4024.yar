rule _20160921_afb633ee817d9b15b91ed82a059939fc_20160921_c07f026b9458_4024 {
  meta:
    description = "datamaliciousorder - from files 20160921_afb633ee817d9b15b91ed82a059939fc.js, 20160921_c07f026b9458324f489ec08b7859e758.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "7a4e330bd3ec71aa3dc8fd3d5b2fa656b04d49cb5ee4e5478a50a6336c5bf9e5"
    hash2       = "ea2be3685bc68d327f9689a9fc4de597314db751f1eacc3ff5fbee0dd0397db0"

  strings:
    $s1 = ";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"Ot\";})(),(function fuck(){return \"Qh\";})(),(function fuc" ascii
    $s2 = ";})(),(function fuck(){return \"UXf\";})(),(function fuck(){return \"Jo\";})(),(function fuck(){return \"NKq\";})(),(function fu" ascii
    $s3 = "tion fuck(){return \"MUs\";})(),(function fuck(){return \"MBg\";})(),(function fuck(){return \"CCb\";})(),(function fuck(){retur" ascii
    $s4 = "ck(){return \"IKv\";})(),(function fuck(){return \"Jo\";})(),(function fuck(){return \"OPz\";})(),(function fuck(){return \"IPu" ascii
    $s5 = "nction fuck(){return \"AUx\";})(),(function fuck(){return \"MOj\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){ret" ascii
    $s6 = "turn \"Dc\";})(),(function fuck(){return \"OQr\";})(),(function fuck(){return \"Yk\";})(),(function fuck(){return \"SUi\";})(),(" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}