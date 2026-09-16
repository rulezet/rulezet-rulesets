rule _20160921_2a4c1d98d0b8022ca5527a8e6d96e6e7_20160921_53ea150fd63a_1192 {
  meta:
    description = "datamaliciousorder - from files 20160921_2a4c1d98d0b8022ca5527a8e6d96e6e7.js, 20160921_53ea150fd63a4ef657412c858a71a13e.js, 20160921_8c33029db61426a234eddfae1623641b.js, 20160921_93e612a2f44e1198dfe3c296cb4f7b79.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "65be7c1c5efef8255d7094d95251c12de72303024061cff2152d54a244a049f0"
    hash2       = "16ac7affa46e10764a6e40de21c545ac275939c77c4acf142df8e3f848362242"
    hash3       = "8a7c2a5271a5dc64c200145fa7252ff19d736174b3556eb436f9ac8941daec71"
    hash4       = "e88aa94cf06df033312260c4a58f453654133758e66e1d2df4f11f9de9bfec7c"

  strings:
    $s1  = "n \"Lp\";})(),(function f000(){return \"Yz\";})(),(function f000(){return \"Vu\";})(),(function f000(){return \"TRc\";})(),(func" ascii
    $s2  = "unction f000(){return \"TRc\";})(),(function f000(){return \"QDg\";})(),(function f000(){return \"Um\";})(),(function f000(){ret" ascii
    $s3  = "Tp\";})(),(function f000(){return \"MDb\";})(),(function f000(){return \"Sj\";})(),(function f000(){return \"SGs\";})(),(functio" ascii
    $s4  = "rn \"WIj\";})(),(function f000(){return \"RPt\";})(),(function f000(){return \"XTn\";})(),(function f000(){return \"ZFe\";})(),(" ascii
    $s5  = "tion f000(){return \"MDb\";})(),(function f000(){return \"PTs\";})(),(function f000(){return \"MJq\";})(),(function f000(){retur" ascii
    $s6  = "{return \"WIj\";})(),(function f000(){return \"KXg\";})(),(function f000(){return \"Yi\";})(),(function f000(){return \"Vj\";})(" ascii
    $s7  = "000(){return \"KDh\";})(),(function f000(){return \"PTi\";})(),(function f000(){return \"Qj\";})(),(function f000(){return \"ZFe" ascii
    $s8  = " f000(){return \"Vj\";})(),(function f000(){return \"Vu\";})(),(function f000(){return \"Zj\";})(),(function f000(){return \"Do" ascii
    $s9  = ";})(),(function f000(){return \"MJq\";})(),(function f000(){return \"DIa\";})(),(function f000(){return \"Zj\";})(),(function f0" ascii
    $s10 = " f000(){return \"RPt\";})(),(function f000(){return \"Vj\";})(),(function f000(){return \"Zj\";})(),(function f000(){return \"Do" ascii
    $s11 = "{return \"IAa\";})(),(function f000(){return \"Lp\";})(),(function f000(){return \"Iq\";})(),(function f000(){return \"GGn\";})(" ascii
    $s12 = "ion f000(){return \"MDb\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"KDh\";})(),(function f000(){return" ascii
    $s13 = "),(function f000(){return \"Qz\";})(),(function f000(){return \"OUx\";})(),(function f000(){return \"MBb\";})(),(function f000()" ascii
    $s14 = "){return \"MDb\";})(),(function f000(){return \"RLk\";})(),(function f000(){return \"Mt\";})(),(function f000(){return \"Kw\";})" ascii
    $s15 = "ion f000(){return \"Qa\";})(),(function f000(){return \"BQb\";})(),(function f000(){return \"Qz\";})(),(function f000(){return " ascii
    $s16 = "g\";})(),(function f000(){return \"Vj\";})(),(function f000(){return \"Vj\";})(),(function f000(){return \"Zj\";})(),(function f" ascii

  condition:
    (uint16(0) == 0x2f0a and (8 of them)
    ) or (all of them)
}