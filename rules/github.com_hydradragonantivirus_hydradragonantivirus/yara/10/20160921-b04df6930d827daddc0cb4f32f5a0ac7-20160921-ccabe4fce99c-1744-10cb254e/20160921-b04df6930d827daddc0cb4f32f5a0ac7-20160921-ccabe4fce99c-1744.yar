rule _20160921_b04df6930d827daddc0cb4f32f5a0ac7_20160921_ccabe4fce99c_1744 {
  meta:
    description = "datamaliciousorder - from files 20160921_b04df6930d827daddc0cb4f32f5a0ac7.js, 20160921_ccabe4fce99c1ebb627aa374a501f33c.js, 20160921_e59567324a545ca23bf9e3ba990b6526.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "20f05e81e91c6d1996527f4c971330eb9446dbb6ad0d88c4d97a9739264f79ba"
    hash2       = "449fe576ee25f77acba5442d771e770819941d7dbf354b5123ca5211ef743189"
    hash3       = "ce1d8f63fc8c7b91e97f36fa89b000d70fc284d08682ca3a91ee6c2a4e6e2c72"

  strings:
    $s1  = "n f000(){return \"IAa\";})(),(function f000(){return \"PTi\";})(),(function f000(){return \"Iq\";})(),(function f000(){return \"" ascii
    $s2  = "000(){return \"UEg\";})(),(function f000(){return \"QDg\";})(),(function f000(){return \"IAa\";})(),(function f000(){return \"ZG" ascii
    $s3  = "eturn \"ZFe\";})(),(function f000(){return \"Oh\";})(),(function f000(){return \"YTp\";})(),(function f000(){return \"Kw\";})()," ascii
    $s4  = "})(),(function f000(){return \"RVb\";})(),(function f000(){return \"Do\";})(),(function f000(){return \"OMd\";})(),(function f00" ascii
    $s5  = "){return \"Wy\";})(),(function f000(){return \"Km\";})(),(function f000(){return \"OUx\";})(),(function f000(){return \"Yv\";})(" ascii
    $s6  = "(),(function f000(){return \"Vj\";})(),(function f000(){return \"UEg\";})(),(function f000(){return \"GGn\";})(),(function f000(" ascii
    $s7  = "(),(function f000(){return \"Nx\";})(),(function f000(){return \"RPt\";})(),(function f000(){return \"TRc\";})(),(function f000(" ascii
    $s8  = "eturn \"Qz\";})(),(function f000(){return \"TRc\";})(),(function f000(){return \"QDg\";})(),(function f000(){return \"Tn\";})()," ascii
    $s9  = "ction f000(){return \"GGn\";})(),(function f000(){return \"Sv\";})(),(function f000(){return \"Tb\";})(),(function f000(){return" ascii
    $s10 = "){return \"DYx\";})(),(function f000(){return \"Lp\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"MDb\";}" ascii
    $s11 = "unction f000(){return \"Go\";})(),(function f000(){return \"Vu\";})(),(function f000(){return \"Nx\";})(),(function f000(){retur" ascii

  condition:
    (uint16(0) == 0x2f0a and (8 of them)
    ) or (all of them)
}