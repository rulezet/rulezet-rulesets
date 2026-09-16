rule _20160921_a977d2870f5e9d12c659565b82cfaa70_20160921_acebc8ac4559_4016 {
  meta:
    description = "datamaliciousorder - from files 20160921_a977d2870f5e9d12c659565b82cfaa70.js, 20160921_acebc8ac4559526a5a8de801968bd19f.js, 20160921_c6572694e5172932491036c67fc9ffe4.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "53eed08aece7cc2a81b9828098c3d3e70042a4891863f1130086a0661fc12870"
    hash2       = "79fe55ec3d2d6dbd854df9676c4565b6a8410e1d94298c2ff2f112036fcfac73"
    hash3       = "e6ae2536ba0486138837b2ae1457fd029e88f0c21975b726f4edd05ba182b08e"

  strings:
    $s1 = "KXg\";})(),(function f000(){return \"KXg\";})(),(function f000(){return \"Yi\";})(),(function f000(){return \"Vj\";})(),(functio" ascii
    $s2 = "rn \"WIj\";})(),(function f000(){return \"IAa\";})(),(function f000(){return \"Tb\";})(),(function f000(){return \"Sq\";})(),(fu" ascii
    $s3 = "return \"Tn\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"MBb\";})(),(function f000(){return \"PTs\";})(" ascii
    $s4 = "f000(){return \"GGn\";})(),(function f000(){return \"DYs\";})(),(function f000(){return \"Yv\";})(),(function f000(){return \"Rh" ascii
    $s5 = " \"Km\";})(),(function f000(){return \"RPt\";})(),(function f000(){return \"OMd\";})(),(function f000(){return \"GGn\";})(),(fun" ascii
    $s6 = "000(){return \"TKl\";})(),(function f000(){return \"OUx\";})(),(function f000(){return \"ZGq\";})(),(function f000(){return \"HJ" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}