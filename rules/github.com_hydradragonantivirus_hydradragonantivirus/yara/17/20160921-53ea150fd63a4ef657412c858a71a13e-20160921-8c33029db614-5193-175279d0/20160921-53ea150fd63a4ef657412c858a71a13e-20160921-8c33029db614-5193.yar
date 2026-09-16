rule _20160921_53ea150fd63a4ef657412c858a71a13e_20160921_8c33029db614_5193 {
  meta:
    description = "datamaliciousorder - from files 20160921_53ea150fd63a4ef657412c858a71a13e.js, 20160921_8c33029db61426a234eddfae1623641b.js, 20160921_93e612a2f44e1198dfe3c296cb4f7b79.js, 20160921_c05dd34a09358454c56b9c248f1d0304.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "16ac7affa46e10764a6e40de21c545ac275939c77c4acf142df8e3f848362242"
    hash2       = "8a7c2a5271a5dc64c200145fa7252ff19d736174b3556eb436f9ac8941daec71"
    hash3       = "e88aa94cf06df033312260c4a58f453654133758e66e1d2df4f11f9de9bfec7c"
    hash4       = "e330ec83e6ac964ffd679e6589494a6108e1995f570c539dee7b1be30953f8a3"

  strings:
    $s1 = " f000(){return \"Qz\";})(),(function f000(){return \"RPt\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"M" ascii
    $s2 = ")(),(function f000(){return \"KXg\";})(),(function f000(){return \"TKl\";})(),(function f000(){return \"TRc\";})(),(function f00" ascii
    $s3 = "\"KXg\";})(),(function f000(){return \"KXg\";})(),(function f000(){return \"XTn\";})(),(function f000(){return \"TRc\";})(),(fun" ascii
    $s4 = "urn \"WIj\";})(),(function f000(){return \"Mu\";})(),(function f000(){return \"XTn\";})(),(function f000(){return \"RPt\";})(),(" ascii
    $s5 = "Gn\";})(),(function f000(){return \"XTn\";})(),(function f000(){return \"Qz\";})(),(function f000(){return \"Yi\";})(),(function" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}