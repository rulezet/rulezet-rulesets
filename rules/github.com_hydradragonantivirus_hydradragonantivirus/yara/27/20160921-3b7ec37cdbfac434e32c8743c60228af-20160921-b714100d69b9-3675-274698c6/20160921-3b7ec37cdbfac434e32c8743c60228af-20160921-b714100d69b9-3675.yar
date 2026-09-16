rule _20160921_3b7ec37cdbfac434e32c8743c60228af_20160921_b714100d69b9_3675 {
  meta:
    description = "datamaliciousorder - from files 20160921_3b7ec37cdbfac434e32c8743c60228af.js, 20160921_b714100d69b955de920a302ff8bef7db.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "86390741cf6e610c2e526db749631548b514c268decade5a5870edfebb141d4b"
    hash2       = "fc43d54db3c24d6f7ce2d47a45ffcd0768d5cfe90e405322e477be98fe4a8170"

  strings:
    $s1 = "),(function fuck(){return \"DRx\";})(),(function fuck(){return \"XFd\";})(),(function fuck(){return \"Sx\";})(),(function fuck()" ascii
    $s2 = "fuck(){return \"Nm\";})(),(function fuck(){return \"YQt\";})(),(function fuck(){return \"Dc\";})(),(function fuck(){return \"IPu" ascii
    $s3 = "\"XFd\";})(),(function fuck(){return \"Sx\";})(),(function fuck(){return \"MOj\";})(),(function fuck(){return \"NKq\";})(),(func" ascii
    $s4 = " fuck(){return \"DRx\";})(),(function fuck(){return \"MIl\";})(),(function fuck(){return \"Jg\";})(),(function fuck(){return \"R" ascii
    $s5 = "(){return \"TTs\";})(),(function fuck(){return \"Vb\";})(),(function fuck(){return \"UOe\";})(),(function fuck(){return \"PDf\";" ascii
    $s6 = "urn \"KVh\";})(),(function fuck(){return \"DRx\";})(),(function fuck(){return \"Yk\";})(),(function fuck(){return \"EHo\";})(),(" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}