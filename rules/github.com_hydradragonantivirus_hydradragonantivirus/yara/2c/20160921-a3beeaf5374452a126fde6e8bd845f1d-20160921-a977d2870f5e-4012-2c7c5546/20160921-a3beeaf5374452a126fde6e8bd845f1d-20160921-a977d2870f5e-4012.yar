rule _20160921_a3beeaf5374452a126fde6e8bd845f1d_20160921_a977d2870f5e_4012 {
  meta:
    description = "datamaliciousorder - from files 20160921_a3beeaf5374452a126fde6e8bd845f1d.js, 20160921_a977d2870f5e9d12c659565b82cfaa70.js, 20160921_c6572694e5172932491036c67fc9ffe4.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "b85118fedd76dd449fd30cfd693681aa77891d92c19c3fa0e9dd14f034e867bb"
    hash2       = "53eed08aece7cc2a81b9828098c3d3e70042a4891863f1130086a0661fc12870"
    hash3       = "e6ae2536ba0486138837b2ae1457fd029e88f0c21975b726f4edd05ba182b08e"

  strings:
    $s1 = ";})(),(function f000(){return \"Qz\";})(),(function f000(){return \"Yi\";})(),(function f000(){return \"DIa\";})(),(function f00" ascii
    $s2 = "tion f000(){return \"MDb\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"Yi\";})(),(function f000(){return" ascii
    $s3 = "ction f000(){return \"Ml\";})(),(function f000(){return \"Tn\";})(),(function f000(){return \"Yz\";})(),(function f000(){return " ascii
    $s4 = "00(){return \"Go\";})(),(function f000(){return \"Yz\";})(),(function f000(){return \"Wy\";})(),(function f000(){return \"Km\";}" ascii
    $s5 = "Gn\";})(),(function f000(){return \"QDg\";})(),(function f000(){return \"Mu\";})(),(function f000(){return \"Yi\";})(),(function" ascii
    $s6 = "eturn \"QDg\";})(),(function f000(){return \"DIa\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"Ut\";})()" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}