rule _20160921_0550bef558fba79f944112d34861e4ec_20160921_3a89132c2088_4228 {
  meta:
    description = "datamaliciousorder - from files 20160921_0550bef558fba79f944112d34861e4ec.js, 20160921_3a89132c20887c3360a3708984b884fb.js, 20160921_86f41d8c83240a68770674107f15f162.js, 20160921_e432cba10cde369693d6b125dda112c7.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "7cc46901b4b691df366f68f1812df531215964f5150686b06997f1f49b536a1c"
    hash2       = "9687ad9b2ded14e00c5b17393de82acd451266863fb217fc6647e1add112f2fd"
    hash3       = "56a4c0b8742284d9e8907df1b8d73d9c73ee82bc9595e88d869c555afd77312d"
    hash4       = "0f0aa2d80d649fb44a67c6ec77b95eb26709057f543ca215edf15a9bcc4bae4b"

  strings:
    $s1 = "0(){return \"MJq\";})(),(function f000(){return \"TKl\";})(),(function f000(){return \"Ml\";})(),(function f000(){return \"Tn\";" ascii
    $s2 = "\"GGn\";})(),(function f000(){return \"QDg\";})(),(function f000(){return \"Go\";})(),(function f000(){return \"HJm\";})(),(func" ascii
    $s3 = ";})(),(function f000(){return \"UEg\";})(),(function f000(){return \"Wy\";})(),(function f000(){return \"Yz\";})(),(function f00" ascii
    $s4 = "nction f000(){return \"Oe\";})(),(function f000(){return \"Yz\";})(),(function f000(){return \"YTp\";})(),(function f000(){retur" ascii
    $s5 = "turn \"Wy\";})(),(function f000(){return \"Oe\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"UOt\";})(),(" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}