rule _20160921_16200453422b5793a6a93d4bb423b0ea_20160921_a1cbb43a1e22_374 {
  meta:
    description = "datamaliciousorder - from files 20160921_16200453422b5793a6a93d4bb423b0ea.js, 20160921_a1cbb43a1e22a4b1fd63ee1a724173eb.js, 20160921_da7f7f057c35b886425ec822f654da90.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "d968eb9bb2807e5889794bf130036c2c81716cd0166eed67a45c9ef3f81607c3"
    hash2       = "4154e4928eccd35fa0d42dbefe4a742700d77124216f8b5756b8ef63634071d3"
    hash3       = "b6935463e925cb13fc2413b3d7559cf8e9f5072c15dc73075977046a3e27e417"

  strings:
    $s1  = "ion f000(){return \"NBs\";})(),(function f000(){return \"Yi\";})(),(function f000(){return \"WIj\";})(),(function f000(){return " ascii
    $s2  = "on f000(){return \"WIj\";})(),(function f000(){return \"Lp\";})(),(function f000(){return \"KXg\";})(),(function f000(){return " ascii
    $s3  = ";})(),(function f000(){return \"KXg\";})(),(function f000(){return \"ZGq\";})(),(function f000(){return \"ZGq\";})(),(function f" ascii
    $s4  = "return \"KXg\";})(),(function f000(){return \"ZGq\";})(),(function f000(){return \"XTn\";})(),(function f000(){return \"TRc\";})" ascii
    $s5  = "nction f000(){return \"OUx\";})(),(function f000(){return \"KXg\";})(),(function f000(){return \"RPt\";})(),(function f000(){ret" ascii
    $s6  = "(){return \"WIj\";})(),(function f000(){return \"Br\";})(),(function f000(){return \"Br\";})(),(function f000(){return \"Zj\";})" ascii
    $s7  = "n f000(){return \"XTn\";})(),(function f000(){return \"Yi\";})(),(function f000(){return \"ZGq\";})(),(function f000(){return \"" ascii
    $s8  = "})(),(function f000(){return \"WIj\";})(),(function f000(){return \"Qj\";})(),(function f000(){return \"RPt\";})(),(function f00" ascii
    $s9  = "n \"GGn\";})(),(function f000(){return \"KXg\";})(),(function f000(){return \"Qz\";})(),(function f000(){return \"KXg\";})(),(fu" ascii
    $s10 = "f000(){return \"Qj\";})(),(function f000(){return \"Kw\";})(),(function f000(){return \"Kw\";})(),(function f000(){return \"Kw\"" ascii
    $s11 = "j\";})(),(function f000(){return \"Qj\";})(),(function f000(){return \"TKl\";})(),(function f000(){return \"ZGq\";})(),(function" ascii
    $s12 = "n f000(){return \"KXg\";})(),(function f000(){return \"ZGq\";})(),(function f000(){return \"TKl\";})(),(function f000(){return " ascii
    $s13 = "turn \"Lp\";})(),(function f000(){return \"Qj\";})(),(function f000(){return \"KXg\";})(),(function f000(){return \"Zj\";})(),(f" ascii
    $s14 = "ion f000(){return \"Qj\";})(),(function f000(){return \"Lp\";})(),(function f000(){return \"RPt\";})(),(function f000(){return " ascii
    $s15 = "(function f000(){return \"OUx\";})(),(function f000(){return \"Qz\";})(),(function f000(){return \"ZGq\";})(),(function f000(){r" ascii
    $s16 = "x\";})(),(function f000(){return \"Mu\";})(),(function f000(){return \"TKl\";})(),(function f000(){return \"ZGq\";})(),(function" ascii
    $s17 = " f000(){return \"Kw\";})(),(function f000(){return \"Kw\";})(),(function f000(){return \"TKl\";})(),(function f000(){return \"ZG" ascii
    $s18 = "0(){return \"Kw\";})(),(function f000(){return \"ZGq\";})(),(function f000(){return \"Yi\";})(),(function f000(){return \"TRc\";" ascii
    $s19 = "turn \"Ot\";})(),(function f000(){return \"Oh\";})(),(function f000(){return \"Sv\";})(),(function f000(){return \"Wb\";})(),(fu" ascii
    $s20 = "Gn\";})(),(function f000(){return \"DNa\";})(),(function f000(){return \"TKp\";})(),(function f000(){return \"KXg\";})(),(functi" ascii

  condition:
    (uint16(0) == 0x2f0a and (8 of them)
    ) or (all of them)
}