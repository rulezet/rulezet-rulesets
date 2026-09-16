rule _20160921_11c4976357ef8a651d058575507518ca_20160921_63a82ecb2e4e_3366 {
  meta:
    description = "datamaliciousorder - from files 20160921_11c4976357ef8a651d058575507518ca.js, 20160921_63a82ecb2e4eb3b0dd878bbec885c469.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "aee597813bd24d68729b505b5e718b120274cb1db588f64e61c1a4eb85f6bf11"
    hash2       = "0e9de62be8773f33e42da56c84c9c85d07f7c2616909543479f7803e6794a9ef"

  strings:
    $s1 = ",(function fuck(){return \"DRx\";})(),(function fuck(){return \"We\";})(),(function fuck(){return \"Wo0\";})(),(function fuck(){" ascii
    $s2 = "k(){return \"Nm\";})(),(function fuck(){return \"Zy\";})(),(function fuck(){return \"SUi\";})(),(function fuck(){return \"Hs\";}" ascii
    $s3 = "function fuck(){return \"TTs\";})(),(function fuck(){return \"YQt\";})(),(function fuck(){return \"Wo0\";})(),(function fuck(){r" ascii
    $s4 = " \"IPu\";})(),(function fuck(){return \"UOe\";})(),(function fuck(){return \"RAi\";})(),(function fuck(){return \"Py\";})(),(fun" ascii
    $s5 = "tion fuck(){return \"IOs\";})(),(function fuck(){return \"UOe\";})(),(function fuck(){return \"DRx\";})(),(function fuck(){retur" ascii
    $s6 = ";})(),(function fuck(){return \"Wo0\";})(),(function fuck(){return \"Py\";})(),(function fuck(){return \"DRx\";})(),(function fu" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}