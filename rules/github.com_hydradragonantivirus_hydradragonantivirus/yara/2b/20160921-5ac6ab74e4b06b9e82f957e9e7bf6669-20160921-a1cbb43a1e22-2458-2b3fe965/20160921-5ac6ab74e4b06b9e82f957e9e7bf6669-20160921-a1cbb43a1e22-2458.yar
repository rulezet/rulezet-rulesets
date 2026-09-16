rule _20160921_5ac6ab74e4b06b9e82f957e9e7bf6669_20160921_a1cbb43a1e22_2458 {
  meta:
    description = "datamaliciousorder - from files 20160921_5ac6ab74e4b06b9e82f957e9e7bf6669.js, 20160921_a1cbb43a1e22a4b1fd63ee1a724173eb.js, 20160921_da7f7f057c35b886425ec822f654da90.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "50225d12c51a2decb97015971f8ce72487a24a69e64ec1d12fd7f720f2320cf3"
    hash2       = "4154e4928eccd35fa0d42dbefe4a742700d77124216f8b5756b8ef63634071d3"
    hash3       = "b6935463e925cb13fc2413b3d7559cf8e9f5072c15dc73075977046a3e27e417"

  strings:
    $s1 = "ion f000(){return \"Sq\";})(),(function f000(){return \"UEg\";})(),(function f000(){return \"DYx\";})(),(function f000(){return " ascii
    $s2 = "){return \"Wy\";})(),(function f000(){return \"QDg\";})(),(function f000(){return \"KDh\";})(),(function f000(){return \"Rh\";})" ascii
    $s3 = "n\";})(),(function f000(){return \"KDh\";})(),(function f000(){return \"Vu\";})(),(function f000(){return \"TKp\";})(),(function" ascii
    $s4 = "on f000(){return \"Rh\";})(),(function f000(){return \"Wy\";})(),(function f000(){return \"Iq\";})(),(function f000(){return \"L" ascii
    $s5 = "})(),(function f000(){return \"WIj\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"TKp\";})(),(function f0" ascii
    $s6 = "RVb\";})(),(function f000(){return \"NYh\";})(),(function f000(){return \"Oe\";})(),(function f000(){return \"Rh\";})(),(functio" ascii
    $s7 = ",(function f000(){return \"Oe\";})(),(function f000(){return \"Qa\";})(),(function f000(){return \"Um\";})(),(function f000(){re" ascii
    $s8 = "\";})(),(function f000(){return \"PTs\";})(),(function f000(){return \"NYh\";})(),(function f000(){return \"XTn\";})(),(function" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}