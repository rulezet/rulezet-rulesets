rule _20160921_178144255388cfaf75832e7c43b7a37d_20160921_28d059ae521d_4518 {
  meta:
    description = "datamaliciousorder - from files 20160921_178144255388cfaf75832e7c43b7a37d.js, 20160921_28d059ae521dbabe2afdc3bfd464938c.js, 20160921_99369f59b90fb2df18b8570f0403febc.js, 20160921_d69f5159aadd1440760083d8952604c6.js, 20160921_e1bc53e337e27af13c4323bd3332a33c.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "ceb222ab2a29064bfa74287cfdb14daf49b9474ead74db04adbe122341895903"
    hash2       = "e141f467019579b96a9cc109c7a3e7efb3b51b1378b450a816089a6ae7d406f7"
    hash3       = "224e0a3dfee910c8afb81d7298f89c0b6e937cbd8062c03cedbe500c3dfe98a2"
    hash4       = "6a93de0a10bfc4b55037c85e12bc3eb9699d5353c4a13a206b5e16e7303d5c86"
    hash5       = "7561e1bb060dd07ca80dc6e0b089a853d0081d60c7843d73299f7dabb92efaea"

  strings:
    $s1 = "nction f000(){return \"Qa\";})(),(function f000(){return \"Um\";})(),(function f000(){return \"RVb\";})(),(function f000(){retur" ascii
    $s2 = "f000(){return \"UEg\";})(),(function f000(){return \"DYx\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"W" ascii
    $s3 = "),(function f000(){return \"GGn\";})(),(function f000(){return \"TKp\";})(),(function f000(){return \"Oe\";})(),(function f000()" ascii
    $s4 = "turn \"Yz\";})(),(function f000(){return \"Tn\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"Sq\";})(),(f" ascii
    $s5 = "n \"EZu\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"ZFe\";})(),(function f000(){return \"Rh\";})(),(fu" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}