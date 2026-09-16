rule _20160921_bfdb187f27d136f64e05f0dcf2ee4914_20160921_c42fb5c75aea_3136 {
  meta:
    description = "datamaliciousorder - from files 20160921_bfdb187f27d136f64e05f0dcf2ee4914.js, 20160921_c42fb5c75aea2648513013ad2eed9aaf.js, 20160921_dc1ff053e9dd688459c33dc98e88d636.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "cbf2173e7b067de6ce6bf189ba38c78f3f0d97a7e6685c0191e08885badfeb3e"
    hash2       = "5c8cdf3dbb94e197c36e5744084d12e198ecdab7243d67654934aa1cc9bf7ae9"
    hash3       = "18a890096a5714e518b28d3f50f6487cfbc4164418daae1842b7d724e2c26bd6"

  strings:
    $s1 = "\"Py\";})(),(function fuck(){return \"MUs\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"AJs\";})(),(func" ascii
    $s2 = "u\";})(),(function fuck(){return \"Ot\";})(),(function fuck(){return \"Qh\";})(),(function fuck(){return \"Dc\";})(),(function f" ascii
    $s3 = " \"DRx\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"XFd\";})(),(function fuck(){return \"Ar\";})(),(fun" ascii
    $s4 = "(function fuck(){return \"IPu\";})(),(function fuck(){return \"OQr\";})(),(function fuck(){return \"Cd\";})(),(function fuck(){r" ascii
    $s5 = "n \"CTm\";})(),(function fuck(){return \"ILp\";})(),(function fuck(){return \"NKq\";})(),(function fuck(){return \"GNm\";})(),(f" ascii
    $s6 = "),(function fuck(){return \"UXf\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"Py\";})(),(function fuck()" ascii
    $s7 = "k(){return \"MBg\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"MIl\";})(),(function fuck(){return \"AUx" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}