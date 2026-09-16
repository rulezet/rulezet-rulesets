rule _20160921_6db2cb585eb933d83d07b47d979b00ec_20160921_afb633ee817d_5375 {
  meta:
    description = "datamaliciousorder - from files 20160921_6db2cb585eb933d83d07b47d979b00ec.js, 20160921_afb633ee817d9b15b91ed82a059939fc.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "b98c5953d102d77c680619bcfd3ba762b3a28a14355f65c479544c745a7c9a12"
    hash2       = "7a4e330bd3ec71aa3dc8fd3d5b2fa656b04d49cb5ee4e5478a50a6336c5bf9e5"

  strings:
    $s1 = "e\";})(),(function fuck(){return \"MIl\";})(),(function fuck(){return \"IOs\";})(),(function fuck(){return \"LGo\";})(),(functio" ascii
    $s2 = "(){return \"DRx\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"Yk\";})(),(function fuck(){return \"FJs\";" ascii
    $s3 = " \"Et\";})(),(function fuck(){return \"Oh\";})(),(function fuck(){return \"Ik\";})(),(function fuck(){return \"IPu\";})(),(funct" ascii
    $s4 = ";})(),(function fuck(){return \"Vb\";})(),(function fuck(){return \"DRx\";})(),(function fuck(){return \"Cd\";})(),(function fuc" ascii
    $s5 = "ction fuck(){return \"Np\";})(),(function fuck(){return \"DRx\";})(),(function fuck(){return \"Cd\";})(),(function fuck(){return" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}