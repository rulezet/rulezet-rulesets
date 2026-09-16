rule _20160921_178144255388cfaf75832e7c43b7a37d_20160921_c9a772728edf_4511 {
  meta:
    description = "datamaliciousorder - from files 20160921_178144255388cfaf75832e7c43b7a37d.js, 20160921_c9a772728edf4eeff48c1aea32c00a13.js, 20160921_d69f5159aadd1440760083d8952604c6.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "ceb222ab2a29064bfa74287cfdb14daf49b9474ead74db04adbe122341895903"
    hash2       = "76f52cefe2f1cf5954919532ecd1ec4c5c9072cb4edc435169d570baa9894ed9"
    hash3       = "6a93de0a10bfc4b55037c85e12bc3eb9699d5353c4a13a206b5e16e7303d5c86"

  strings:
    $s1 = "{return \"GGn\";})(),(function f000(){return \"Rh\";})(),(function f000(){return \"DYx\";})(),(function f000(){return \"TKp\";})" ascii
    $s2 = "tion f000(){return \"Wy\";})(),(function f000(){return \"QDg\";})(),(function f000(){return \"Do\";})(),(function f000(){return " ascii
    $s3 = "})(),(function f000(){return \"Oe\";})(),(function f000(){return \"Zj\";})(),(function f000(){return \"KZr\";})(),(function f000" ascii
    $s4 = "(){return \"Ml\";})(),(function f000(){return \"Tb\";})(),(function f000(){return \"SGs\";})(),(function f000(){return \"Iq\";})" ascii
    $s5 = "function f000(){return \"QDg\";})(),(function f000(){return \"RPt\";})(),(function f000(){return \"Do\";})(),(function f000(){re" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}