rule _20160921_1f7d568f432abb102bc2d5dbd6c68c22_20160921_24cca85b9483_4635 {
  meta:
    description = "datamaliciousorder - from files 20160921_1f7d568f432abb102bc2d5dbd6c68c22.js, 20160921_24cca85b9483630d2e2e50bdd8aa5013.js, 20160921_28d059ae521dbabe2afdc3bfd464938c.js, 20160921_297b9b66086a46a28327ea94b4a62e58.js, 20160921_2b1783136e2caa674fa83100212e0871.js, 20160921_3d472332b6f7d53a9f60478e1312ea58.js, 20160921_40c9b3a004789873984432b531f4fb80.js, 20160921_6167c3d38189e7b1134d16083ffbd574.js, 20160921_7912bf3790296273bb8c94248adbbc9a.js, 20160921_a4213841acc34547cdaa9cab58f8e2d8.js, 20160921_a864250b4ae6162ed0d7a2f3ed785d46.js, 20160921_c05dd34a09358454c56b9c248f1d0304.js, 20160921_daba59e7a6b9ed6983cd2cbef1eb1597.js, 20160921_ded524cdc972424d0fa8254648795d71.js, 20160921_e1bc53e337e27af13c4323bd3332a33c.js, 20160921_f1b8df0ab75abc0c2b3be738559f2ab3.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "193a02aff0ca7f757ef6d01358baac9c7338cd556144a08982dce9382eff6344"
    hash2       = "59d00368c1188c6d6bc66f675b72e99608dc018c3528d523610abc2745ea88cd"
    hash3       = "e141f467019579b96a9cc109c7a3e7efb3b51b1378b450a816089a6ae7d406f7"
    hash4       = "4d719bbec78475fb1d00242f1258699600032a10dd821cc9dfec2254bbe341f7"
    hash5       = "4f4f696f319827ea3bc8e0b927eddbd7a588f390148cae3276f1573d816d8889"
    hash6       = "afa09723c03c97cb533583268f8fb586a7ccfc3438d793acc59eedb90be55b5b"
    hash7       = "b913ca9b6976b1846b7d36cab5b8fc09147f8eda84e9fde77f0aab4dfe5a2ab3"
    hash8       = "02d7a73acd6af9940f585a0e89095467489ba0ac094eb93050d43dab5745e5bd"
    hash9       = "3bf106f8ef0e4b03e869f1cf914513f711eb52824441a1f2740f3faec2821404"
    hash10      = "3bdfe74e5399936e0bca26e7caeb97bfdab7631164f7ae885438865cb52fa076"
    hash11      = "f64f9f9fd1a5e4b096281bd9733f52c453683cc9032801264dd73f202b17964f"
    hash12      = "e330ec83e6ac964ffd679e6589494a6108e1995f570c539dee7b1be30953f8a3"
    hash13      = "94c619539e853fdec1958270da7516c52bbcf442ee9ca0569d11e19e70ae29eb"
    hash14      = "09c4ea683259322d1696083646a9b96190b4796e8b3fdf91ba2bf4f6296afaa9"
    hash15      = "7561e1bb060dd07ca80dc6e0b089a853d0081d60c7843d73299f7dabb92efaea"
    hash16      = "dfdf24fc382cd60cf8d9c01ff0bca33ee060801ad2bd963895209ac610525301"

  strings:
    $s1 = "(function f000(){return \"Br\";})(),(function f000(){return \"UEg\";})(),(function f000(){return \"Wy\";})(),(function f000(){re" ascii
    $s2 = "function f000(){return \"GGn\";})(),(function f000(){return \"Br\";})(),(function f000(){return \"Vj\";})(),(function f000(){ret" ascii
    $s3 = "Dh\";})(),(function f000(){return \"HJm\";})(),(function f000(){return \"HJm\";})(),(function f000(){return \"Br\";})(),(functio" ascii
    $s4 = "00(){return \"UEg\";})(),(function f000(){return \"Qz\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"WIj" ascii
    $s5 = "n \"GGn\";})(),(function f000(){return \"Qa\";})(),(function f000(){return \"Nv\";})(),(function f000(){return \"DYx\";})(),(fun" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}