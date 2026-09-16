rule _20160921_57d7efd4078096b801e379ee02f0feec_20160921_a8b3df7e98e8_5225 {
  meta:
    description = "datamaliciousorder - from files 20160921_57d7efd4078096b801e379ee02f0feec.js, 20160921_a8b3df7e98e8a886568b517b6d357d72.js, 20160921_ac32e5db1761db7bcee12f6443e4be71.js, 20160921_ad0fbcfca87e48302530672c4ceab093.js, 20160921_b04f9fe7316d0e86c0046e130e905e37.js, 20160921_b9eadd20f28216849138290cb6dac4de.js, 20160921_cb95437e5f7b0cd43bdbd6381ee6a105.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "e568760a55d343665c530313749711c3424bfd35c792b1a8b1d5ad6fa004c9a6"
    hash2       = "0652be8fe8ee502a5c45d7c0d1b7f5ea93bd8633350801afbb4709b88afc93e2"
    hash3       = "c720e572402df240156cf5af93a10b135edc995ca3aaedbfe6a9673216f7c930"
    hash4       = "481451a3850055fd2d398d5707171f67d2aa3cd019214d6b67f539efc81ca7bb"
    hash5       = "58df336ac7568c9f52fedec5d0b900480491f3e65f56c23426010ec745a6bddd"
    hash6       = "4859166acfe74b9a623acc55b045aff7a4c46e4f5c457bb304c5169c6e7fb4a9"
    hash7       = "46d771acb80357bcbb0857af9e7a4a35304fdbbf9785ec02f88f92f1268dfa71"

  strings:
    $s1 = "function fuck(){return \"QTc\";})(),(function fuck(){return \"Dc\";})(),(function fuck(){return \"YAv\";})(),(function fuck(){re" ascii
    $s2 = "n \"Ik\";})(),(function fuck(){return \"Fv\";})(),(function fuck(){return \"Xg\";})(),(function fuck(){return \"IPu\";})(),(func" ascii
    $s3 = "tion fuck(){return \"Za\";})(),(function fuck(){return \"Xg\";})(),(function fuck(){return \"Ik\";})(),(function fuck(){return " ascii
    $s4 = "){return \"ZLd\";})(),(function fuck(){return \"Sx\";})(),(function fuck(){return \"UOe\";})(),(function fuck(){return \"Pc\";})" ascii
    $s5 = "Xg\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"OQr\";})(),(function fuck(){return \"Vf\";})(),(functio" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}