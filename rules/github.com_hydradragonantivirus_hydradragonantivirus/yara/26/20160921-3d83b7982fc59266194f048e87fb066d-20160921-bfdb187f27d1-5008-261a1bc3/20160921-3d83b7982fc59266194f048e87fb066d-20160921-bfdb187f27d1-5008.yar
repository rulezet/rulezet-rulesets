rule _20160921_3d83b7982fc59266194f048e87fb066d_20160921_bfdb187f27d1_5008 {
  meta:
    description = "datamaliciousorder - from files 20160921_3d83b7982fc59266194f048e87fb066d.js, 20160921_bfdb187f27d136f64e05f0dcf2ee4914.js, 20160921_c42fb5c75aea2648513013ad2eed9aaf.js, 20160921_dc1ff053e9dd688459c33dc98e88d636.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "f14778492463eaa86aec448221dcd9e88defb1f42404b2b80d42b0d0c41ffa66"
    hash2       = "cbf2173e7b067de6ce6bf189ba38c78f3f0d97a7e6685c0191e08885badfeb3e"
    hash3       = "5c8cdf3dbb94e197c36e5744084d12e198ecdab7243d67654934aa1cc9bf7ae9"
    hash4       = "18a890096a5714e518b28d3f50f6487cfbc4164418daae1842b7d724e2c26bd6"

  strings:
    $s1 = "unction fuck(){return \"Ve\";})(),(function fuck(){return \"Za\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){retu" ascii
    $s2 = "on fuck(){return \"OQr\";})(),(function fuck(){return \"Qh\";})(),(function fuck(){return \"Ve\";})(),(function fuck(){return \"" ascii
    $s3 = "urn \"MBg\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"Oh\";})(),(function fuck(){return \"Jh\";})(),(f" ascii
    $s4 = "ion fuck(){return \"Jg\";})(),(function fuck(){return \"GNm\";})(),(function fuck(){return \"Bz\";})(),(function fuck(){return " ascii
    $s5 = "tion fuck(){return \"CTm\";})(),(function fuck(){return \"CTm\";})(),(function fuck(){return \"CTm\";})(),(function fuck(){retur" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}