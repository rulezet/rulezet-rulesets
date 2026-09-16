rule _20160921_8b0f3892ae56f8c06d3baa62c262a12f_20160922_b22dda4c9fbc_937 {
  meta:
    description = "datamaliciousorder - from files 20160921_8b0f3892ae56f8c06d3baa62c262a12f.js, 20160922_b22dda4c9fbc74ba5e251fc3110ada5a.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "96514db18a22f5e5bde10feb1f6b426e5772d0f7e76f227e8d49a7a00bfb01b7"
    hash2       = "946b208e84c64dbffc7e1cb08a19f629639d795decea5bf8ddd08b34a59e5e59"

  strings:
    $s1  = "){return \"Qa\";})(),(function f000(){return \"TKl\";})(),(function f000(){return \"XTn\";})(),(function f000(){return \"GGn\";}" ascii
    $s2  = "n \"Mu\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"ZFe\";})(),(function f000(){return \"XTn\";})(),(fu" ascii
    $s3  = "00(){return \"Nv\";})(),(function f000(){return \"Vj\";})(),(function f000(){return \"Wy\";})(),(function f000(){return \"XTn\";" ascii
    $s4  = "Xg\";})(),(function f000(){return \"TKl\";})(),(function f000(){return \"ZFe\";})(),(function f000(){return \"Zj\";})(),(functio" ascii
    $s5  = "n f000(){return \"DYx\";})(),(function f000(){return \"MJq\";})(),(function f000(){return \"QDg\";})(),(function f000(){return " ascii
    $s6  = "f000(){return \"UEg\";})(),(function f000(){return \"OUx\";})(),(function f000(){return \"ZFe\";})(),(function f000(){return \"X" ascii
    $s7  = "(),(function f000(){return \"Yz\";})(),(function f000(){return \"TKp\";})(),(function f000(){return \"IPu\";})(),(function f000(" ascii
    $s8  = "000(){return \"Do\";})(),(function f000(){return \"TRc\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"Fs" ascii
    $s9  = "urn \"GGn\";})(),(function f000(){return \"QDg\";})(),(function f000(){return \"KXg\";})(),(function f000(){return \"ZFe\";})()," ascii
    $s10 = "n f000(){return \"GGn\";})(),(function f000(){return \"UEg\";})(),(function f000(){return \"OUx\";})(),(function f000(){return " ascii
    $s11 = "eturn \"TKl\";})(),(function f000(){return \"RPt\";})(),(function f000(){return \"ZFe\";})(),(function f000(){return \"Yi\";})()" ascii
    $s12 = ";})(),(function f000(){return \"Do\";})(),(function f000(){return \"ZFe\";})(),(function f000(){return \"GGn\";})(),(function f0" ascii
    $s13 = "eturn \"Do\";})(),(function f000(){return \"Yi\";})(),(function f000(){return \"KXg\";})(),(function f000(){return \"Yi\";})(),(" ascii
    $s14 = "\";})(),(function f000(){return \"ZFe\";})(),(function f000(){return \"XTn\";})(),(function f000(){return \"DIa\";})(),(function" ascii
    $s15 = "\";})(),(function f000(){return \"Do\";})(),(function f000(){return \"KXg\";})(),(function f000(){return \"TKl\";})(),(function " ascii
    $s16 = "on f000(){return \"RPt\";})(),(function f000(){return \"Do\";})(),(function f000(){return \"TRc\";})(),(function f000(){return " ascii
    $s17 = "function f000(){return \"GGn\";})(),(function f000(){return \"Yi\";})(),(function f000(){return \"Do\";})(),(function f000(){ret" ascii
    $s18 = "rn \"Oe\";})(),(function f000(){return \"OMd\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"UEg\";})(),(f" ascii
    $s19 = "unction f000(){return \"Do\";})(),(function f000(){return \"TRc\";})(),(function f000(){return \"Wh\";})(),(function f000(){retu" ascii
    $s20 = "turn \"XTn\";})(),(function f000(){return \"KXg\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"Ut\";})()," ascii

  condition:
    (uint16(0) == 0x2f0a and (8 of them)
    ) or (all of them)
}