rule _20160921_87f13d652177c2ccba1196dd341efb6d_20160921_a977d2870f5e_3959 {
  meta:
    description = "datamaliciousorder - from files 20160921_87f13d652177c2ccba1196dd341efb6d.js, 20160921_a977d2870f5e9d12c659565b82cfaa70.js, 20160921_ad69715850fae108d9a16055efb4f51c.js, 20160921_c6572694e5172932491036c67fc9ffe4.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "52cce778f06a6477b6f4a6a9f48328a81d874164235533c2925fdd358b6279c3"
    hash2       = "53eed08aece7cc2a81b9828098c3d3e70042a4891863f1130086a0661fc12870"
    hash3       = "76ed8c5c3ace4ce119f1561d5d61ca2e454da79e9156a8397e72d6eed3a22d74"
    hash4       = "e6ae2536ba0486138837b2ae1457fd029e88f0c21975b726f4edd05ba182b08e"

  strings:
    $s1 = "\"MJq\";})(),(function f000(){return \"YTp\";})(),(function f000(){return \"TKl\";})(),(function f000(){return \"Vj\";})(),(func" ascii
    $s2 = "0(){return \"Br\";})(),(function f000(){return \"DIa\";})(),(function f000(){return \"Do\";})(),(function f000(){return \"MKa\";" ascii
    $s3 = "turn \"GGn\";})(),(function f000(){return \"Nv\";})(),(function f000(){return \"Sj\";})(),(function f000(){return \"UEg\";})(),(" ascii
    $s4 = "rn \"Yz\";})(),(function f000(){return \"UEg\";})(),(function f000(){return \"Oe\";})(),(function f000(){return \"QDg\";})(),(fu" ascii
    $s5 = "ion f000(){return \"DYx\";})(),(function f000(){return \"Sj\";})(),(function f000(){return \"DYx\";})(),(function f000(){return " ascii
    $s6 = ")(),(function f000(){return \"Oe\";})(),(function f000(){return \"Tn\";})(),(function f000(){return \"DYs\";})(),(function f000(" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}