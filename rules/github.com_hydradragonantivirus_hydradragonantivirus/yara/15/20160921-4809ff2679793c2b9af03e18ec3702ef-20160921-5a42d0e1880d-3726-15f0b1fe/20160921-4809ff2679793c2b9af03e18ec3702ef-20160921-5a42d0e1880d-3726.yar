rule _20160921_4809ff2679793c2b9af03e18ec3702ef_20160921_5a42d0e1880d_3726 {
  meta:
    description = "datamaliciousorder - from files 20160921_4809ff2679793c2b9af03e18ec3702ef.js, 20160921_5a42d0e1880d178346694a30bc112076.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "2c2d464143196a0237396460d274213cf5b3de772f4205aee0525b67ca1bfd6c"
    hash2       = "ca8e81eec437e87b27dedb202751f13e736aa092e78fffde5fbf40616f2e3738"

  strings:
    $s1 = "return \"Cd\";})(),(function fuck(){return \"Ve\";})(),(function fuck(){return \"MUs\";})(),(function fuck(){return \"RAi\";})()" ascii
    $s2 = "return \"IPu\";})(),(function fuck(){return \"Hs\";})(),(function fuck(){return \"USf\";})(),(function fuck(){return \"Hs\";})()" ascii
    $s3 = "tion fuck(){return \"OPz\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"Cd\";})(),(function fuck(){return" ascii
    $s4 = "uck(){return \"Hs\";})(),(function fuck(){return \"USf\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"Ml" ascii
    $s5 = "n \"USf\";})(),(function fuck(){return \"TTs\";})(),(function fuck(){return \"Jo\";})(),(function fuck(){return \"UOe\";})(),(fu" ascii
    $s6 = "eturn \"DRx\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"XFd\";})(),(function fuck(){return \"Cd\";})()" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}