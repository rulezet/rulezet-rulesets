rule _20160921_20daf816cda5af37e984359023f15db2_20160921_70b567ca258b_4663 {
  meta:
    description = "datamaliciousorder - from files 20160921_20daf816cda5af37e984359023f15db2.js, 20160921_70b567ca258b3c505e14f3c712366f09.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "a45ccf6470d4ee194ed220125c42c5ac5d7c4b8a46cce738c6d12e9cc0bafea8"
    hash2       = "8cf06551c554a2db81fe1bf37b069b40e558f931913e7d2572bdd18b36f57c73"

  strings:
    $s1 = "),(function fuck(){return \"Dc\";})(),(function fuck(){return \"OQr\";})(),(function fuck(){return \"Yk\";})(),(function fuck(){" ascii
    $s2 = "ction fuck(){return \"DRx\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"Nm\";})(),(function fuck(){retur" ascii
    $s3 = "Pu\";})(),(function fuck(){return \"CCb\";})(),(function fuck(){return \"XHj\";})(),(function fuck(){return \"IOs\";})(),(functi" ascii
    $s4 = "k(){return \"Jh\";})(),(function fuck(){return \"USf\";})(),(function fuck(){return \"TTs\";})(),(function fuck(){return \"Jo\";" ascii
    $s5 = "(){return \"To\";})(),(function fuck(){return \"DWe\";})(),(function fuck(){return \"Sx\";})(),(function fuck(){return \"IPu\";}" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}