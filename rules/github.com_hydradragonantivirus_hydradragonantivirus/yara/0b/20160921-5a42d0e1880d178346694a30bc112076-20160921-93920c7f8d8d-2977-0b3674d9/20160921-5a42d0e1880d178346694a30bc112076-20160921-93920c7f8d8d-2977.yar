rule _20160921_5a42d0e1880d178346694a30bc112076_20160921_93920c7f8d8d_2977 {
  meta:
    description = "datamaliciousorder - from files 20160921_5a42d0e1880d178346694a30bc112076.js, 20160921_93920c7f8d8dcef0135d270226e913f5.js, 20160921_d414cec9501c17802073a2f8f7b005c4.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "ca8e81eec437e87b27dedb202751f13e736aa092e78fffde5fbf40616f2e3738"
    hash2       = "a340a8acce75472b10972c1d41244236fbd98f0f2ecd9effbe64bc76604b8eb6"
    hash3       = "65e6cb34b6f46aaa1020cec9a648634a1eceb7e9d6ad0387fc939923e8236594"

  strings:
    $s1 = " \"Wo0\";})(),(function fuck(){return \"MOj\";})(),(function fuck(){return \"NKq\";})(),(function fuck(){return \"GNm\";})(),(fu" ascii
    $s2 = "){return \"Pc\";})(),(function fuck(){return \"Ve\";})(),(function fuck(){return \"Xg\";})(),(function fuck(){return \"Fv\";})()" ascii
    $s3 = "turn \"Fv\";})(),(function fuck(){return \"QTc\";})(),(function fuck(){return \"NKq\";})(),(function fuck(){return \"GNm\";})()," ascii
    $s4 = "on fuck(){return \"Ug\";})(),(function fuck(){return \"Dc\";})(),(function fuck(){return \"YAv\";})(),(function fuck(){return \"" ascii
    $s5 = "(){return \"IPu\";})(),(function fuck(){return \"Nm\";})(),(function fuck(){return \"MUs\";})(),(function fuck(){return \"Pc\";}" ascii
    $s6 = ";})(),(function fuck(){return \"Fv\";})(),(function fuck(){return \"XFd\";})(),(function fuck(){return \"Ik\";})(),(function fuc" ascii
    $s7 = "Nm\";})(),(function fuck(){return \"Wo0\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"MBg\";})(),(functi" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}