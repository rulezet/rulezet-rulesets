rule _20160921_08977f7f9e06ddd41f6d4c2067611fb8_20160921_3e5e21af311d_4303 {
  meta:
    description = "datamaliciousorder - from files 20160921_08977f7f9e06ddd41f6d4c2067611fb8.js, 20160921_3e5e21af311d364f73107419b54e74e3.js, 20160921_a1cbb43a1e22a4b1fd63ee1a724173eb.js, 20160921_a2977e58d35241f07c3f294ca2097899.js, 20160921_da7f7f057c35b886425ec822f654da90.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "7bfc954e02f30b2a7d9d67f82866d129c9944d4c1b1a2d6e89bf77f6d6c9f997"
    hash2       = "8b6cb861af32c3db5ac97103bfe3b904e62a9eee40ed51764665b556005b9510"
    hash3       = "4154e4928eccd35fa0d42dbefe4a742700d77124216f8b5756b8ef63634071d3"
    hash4       = "e73f1b219b8d754435de05b984a60d0a49eb426ffb33ef307d21a1f8ee6a7880"
    hash5       = "b6935463e925cb13fc2413b3d7559cf8e9f5072c15dc73075977046a3e27e417"

  strings:
    $s1 = "})(),(function f000(){return \"WIj\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"RLk\";})(),(function f0" ascii
    $s2 = "{return \"Sq\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"QDg\";})(),(function f000(){return \"ZFe\";})" ascii
    $s3 = "n \"OUx\";})(),(function f000(){return \"TRc\";})(),(function f000(){return \"Zj\";})(),(function f000(){return \"KZr\";})(),(fu" ascii
    $s4 = "tion f000(){return \"Yv\";})(),(function f000(){return \"Sq\";})(),(function f000(){return \"GGn\";})(),(function f000(){return " ascii
    $s5 = "eturn \"Wb\";})(),(function f000(){return \"DIa\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"BIj\";})()" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}