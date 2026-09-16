rule _20160921_4cbbeff2b84f01cc3ab55f4eb29babb2_20160921_e63dc8126cee_2943 {
  meta:
    description = "datamaliciousorder - from files 20160921_4cbbeff2b84f01cc3ab55f4eb29babb2.js, 20160921_e63dc8126cee826e8d941c1665ea92b4.js, 20160921_f5230fc58405f25233bda6815654bd6e.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "698c46439ef391a98b04ac1a2759ff8a84b30a9c444a7575c5290eb0aa4b66b9"
    hash2       = "b87ae77185b5925bd9480daa9d4b74b2291cc670108bf85e0379579434ebff34"
    hash3       = "1a813dda7d0088c45bb00563ea79982995ec1337c805380117fe705f80c51c64"

  strings:
    $s1 = "fuck(){return \"Jo\";})(),(function fuck(){return \"Hs\";})(),(function fuck(){return \"UOe\";})(),(function fuck(){return \"LGo" ascii
    $s2 = "(),(function fuck(){return \"Jo\";})(),(function fuck(){return \"RAi\";})(),(function fuck(){return \"RAi\";})(),(function fuck(" ascii
    $s3 = " fuck(){return \"Oh\";})(),(function fuck(){return \"Ug\";})(),(function fuck(){return \"KVh\";})(),(function fuck(){return \"Vb" ascii
    $s4 = "nction fuck(){return \"Nm\";})(),(function fuck(){return \"Wo\";})(),(function fuck(){return \"MUs\";})(),(function fuck(){retur" ascii
    $s5 = "),(function fuck(){return \"OQr\";})(),(function fuck(){return \"XFd\";})(),(function fuck(){return \"SUi\";})(),(function fuck(" ascii
    $s6 = " \"YQt\";})(),(function fuck(){return \"Sx\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"DRx\";})(),(fun" ascii
    $s7 = "{return \"DRx\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"YQt\";})(),(function fuck(){return \"QTc\";}" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}